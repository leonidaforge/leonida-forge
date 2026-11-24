//! Recognition of the static RPF9 cipher descriptor.
//!
//! The descriptor writer is located by its instruction body, revalidated by
//! decoding, and its callers are bounded with the PE exception table. Each
//! descriptor-building path is decoded into basic blocks: a block that jumps to
//! the call block sets the key identifier, the cipher type, the parameter
//! pointer and the descriptor object. Equality tests on the selector index map
//! each path to one index; a path that maps to more than one index is
//! ambiguous.
//!
//! The writer body is a build-specific instruction seed. Recognition is not
//! compiler-generic: a different writer or selector dispatch fails closed with
//! [`DescriptorError::UnsupportedLayout`] instead of guessing.
//!
//! Decoding uses `iced-x86` in 64-bit mode. Only the operand and control-flow
//! checks described above are interpreted; this is not a general-purpose
//! reverse-engineering engine, and no external disassembler is required.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, MemorySize, Mnemonic, OpKind, Register,
};
use lforge_binary::pe::{ExecutableView, Section};

use super::{Limits, Registry, RegistryError, STATIC_STEP1_MODE, StaticDescriptor};
use crate::rpf::metadata::transform::Algorithm;

/// The static descriptor writer's body. Every hit is revalidated by decoding;
/// this seed is specific to the inspected build.
pub(super) const WRITER_PATTERN: [u8; 30] = [
    0xC5, 0xF8, 0x57, 0xC0, // vxorps xmm0, xmm0, xmm0
    0x89, 0x11, // mov dword [rcx], edx
    0x66, 0x44, 0x89, 0x41, 0x04, // mov word [rcx+4], r8w
    0x48, 0x89, 0xC8, // mov rcx, rax
    0xC5, 0xF8, 0x11, 0x41, 0x06, // vmovups [rcx+6], xmm0
    0xC4, 0xC1, 0x78, 0x10, 0x01, // vmovups xmm0, [r9]
    0xC5, 0xF8, 0x11, 0x41, 0x06, // vmovups [rcx+6], xmm0
    0xC3, // ret
];

/// Bytes of one RUNTIME_FUNCTION entry.
const RUNTIME_FUNCTION_LEN: usize = 12;
/// Raw bytes read per search step.
const SEARCH_CHUNK: usize = 1024 * 1024;
/// Writer hits the search accepts before failing.
const MAX_WRITER_HITS: usize = 64;
/// Call sites the recognizer accepts before failing.
const MAX_CALL_SITES: usize = 64;
/// Bytes of an exception table the recognizer accepts.
const MAX_EXCEPTION_BYTES: u64 = 64 * 1024 * 1024;
/// Blocks a reachability check visits.
const REACHABLE_LIMIT: usize = 512;
/// Instructions between cancellation checks.
const CANCEL_CHECK_INSTRUCTIONS: usize = 4096;
/// Instructions inspected after a comparison for its conditional branch.
const BRANCH_LOOKAHEAD: usize = 3;
/// Bytes of the descriptor object the writer writes.
const DESCRIPTOR_OBJECT_LEN: u64 = 0x16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescriptorError {
    /// No instruction sequence matches the descriptor writer.
    WriterNotFound,
    /// More than one instruction sequence matches the descriptor writer.
    WriterAmbiguous,
    /// The selected selector index has no descriptor path.
    DescriptorNotFound,
    /// More than one descriptor path maps to the selected index.
    DescriptorAmbiguous,
    /// One descriptor path maps to more than one selector index.
    AmbiguousMapping,
    /// The descriptor's cipher type does not select algorithm `0x10`.
    UnsupportedCipher,
    /// The descriptor parameter cannot be read as 16 bytes.
    MalformedParameter,
    /// The descriptor object is not inside the image.
    MalformedObject,
    /// The executable layout is not one this recognizer can interpret.
    UnsupportedLayout(&'static str),
    /// The descriptor's selector has no registry state.
    NoCompatibleState,
    /// The descriptor's selector has more than one registry state.
    StateAmbiguous,
    /// The resolved registry state is not a valid encoded key state.
    StateMalformed,
    /// A limit was exceeded.
    ResourceLimit { what: &'static str, limit: u64 },
    /// The caller cancelled the analysis.
    Cancelled,
    /// The executable could not be read.
    Image(&'static str),
}

impl fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DescriptorError::WriterNotFound => {
                f.write_str("the static descriptor writer was not found")
            }
            DescriptorError::WriterAmbiguous => {
                f.write_str("more than one static descriptor writer")
            }
            DescriptorError::DescriptorNotFound => {
                f.write_str("no static descriptor for the archive selector")
            }
            DescriptorError::DescriptorAmbiguous => {
                f.write_str("more than one static descriptor for the archive selector")
            }
            DescriptorError::AmbiguousMapping => {
                f.write_str("a descriptor path maps to more than one selector index")
            }
            DescriptorError::UnsupportedCipher => {
                f.write_str("the static descriptor's cipher type is not supported")
            }
            DescriptorError::MalformedParameter => {
                f.write_str("the static descriptor's parameter is malformed")
            }
            DescriptorError::MalformedObject => {
                f.write_str("the static descriptor object is malformed")
            }
            DescriptorError::UnsupportedLayout(reason) => {
                write!(f, "unsupported executable layout: {reason}")
            }
            DescriptorError::NoCompatibleState => {
                f.write_str("no compatible key state for the static descriptor")
            }
            DescriptorError::StateAmbiguous => {
                f.write_str("more than one key state for the static descriptor")
            }
            DescriptorError::StateMalformed => {
                f.write_str("the static descriptor's key state is malformed")
            }
            DescriptorError::ResourceLimit { what, limit } => {
                write!(f, "the {what} exceeds the limit of {limit}")
            }
            DescriptorError::Cancelled => f.write_str("cancelled"),
            DescriptorError::Image(reason) => {
                write!(f, "the executable could not be read: {reason}")
            }
        }
    }
}

impl std::error::Error for DescriptorError {}

fn resource(what: &'static str, limit: u64) -> DescriptorError {
    DescriptorError::ResourceLimit { what, limit }
}

fn unsupported(reason: &'static str) -> DescriptorError {
    DescriptorError::UnsupportedLayout(reason)
}

/// Recognizes the static descriptor that `archive_selector` selects and
/// verifies that its key identifier resolves to exactly one valid state in
/// `registry`.
pub fn recognize_static_descriptor(
    image: &ExecutableView,
    registry: &Registry,
    archive_selector: u8,
    cancel: &AtomicBool,
) -> Result<StaticDescriptor, DescriptorError> {
    recognize_with(image, registry, archive_selector, cancel, Limits::default())
}

pub(crate) fn recognize_with(
    image: &ExecutableView,
    registry: &Registry,
    archive_selector: u8,
    cancel: &AtomicBool,
    limits: Limits,
) -> Result<StaticDescriptor, DescriptorError> {
    let index = archive_selector >> 1;
    let sections = code_sections(image);
    if sections.is_empty() {
        return Err(unsupported("the executable has no readable code section"));
    }

    let writer = find_writer(image, &sections, cancel)?;
    let calls = find_call_sites(image, &sections, writer, cancel)?;
    if calls.is_empty() {
        return Err(DescriptorError::DescriptorNotFound);
    }
    let functions = exception_functions(image)?;

    let mut found: Vec<Found> = Vec::new();
    let mut ambiguous_mapping = false;
    let mut unknown_bounds = 0usize;
    let mut analyzed = 0usize;
    for call in calls {
        let Some((start, end)) = containing_function(&functions, call)? else {
            unknown_bounds += 1;
            continue;
        };
        let instructions = decode_function(image, start, end, cancel, &limits)?;
        let blocks = Blocks::build(&instructions)?;
        let call_block = blocks
            .block_of_address(call)
            .ok_or(unsupported("a descriptor writer call is undecoded"))?;
        analyzed += 1;
        for tuple in blocks.descriptor_tuples(call_block) {
            let indices = blocks.indices_for(tuple.block);
            match indices.as_slice() {
                [] => {}
                [index] => found.push(Found {
                    index: *index,
                    tuple,
                }),
                _ => ambiguous_mapping = true,
            }
        }
    }

    if ambiguous_mapping {
        return Err(DescriptorError::AmbiguousMapping);
    }
    if found.is_empty() {
        if unknown_bounds > 0 {
            return Err(unsupported(
                "the function bounds of a descriptor writer call are unknown",
            ));
        }
        if analyzed > 0 {
            return Err(unsupported(
                "the descriptor builder layout is not supported",
            ));
        }
        return Err(DescriptorError::DescriptorNotFound);
    }

    let mut matches = found.iter().filter(|found| found.index == u64::from(index));
    let tuple = match (matches.next(), matches.next()) {
        (Some(Found { tuple, .. }), None) => *tuple,
        (None, _) => return Err(DescriptorError::DescriptorNotFound),
        (Some(_), Some(_)) => return Err(DescriptorError::DescriptorAmbiguous),
    };

    let algorithm = match Algorithm::of(tuple.kind) {
        Ok(algorithm @ Algorithm::Cbc) => algorithm,
        _ => return Err(DescriptorError::UnsupportedCipher),
    };
    let parameter = read_parameter(image, tuple.parameter_va)?;
    if !mapped_range(image, tuple.object_va, DESCRIPTOR_OBJECT_LEN) {
        return Err(DescriptorError::MalformedObject);
    }
    registry
        .state_for_key(tuple.key_id, algorithm.id(), STATIC_STEP1_MODE)
        .map_err(map_registry)?;

    Ok(StaticDescriptor::new(
        index,
        tuple.key_id,
        tuple.kind,
        parameter,
    ))
}

fn map_registry(error: RegistryError) -> DescriptorError {
    match error {
        RegistryError::NoCompatibleState | RegistryError::NotFound => {
            DescriptorError::NoCompatibleState
        }
        RegistryError::Ambiguous => DescriptorError::StateAmbiguous,
        RegistryError::StateMalformed(_) => DescriptorError::StateMalformed,
        RegistryError::ResourceLimit { what, limit } => {
            DescriptorError::ResourceLimit { what, limit }
        }
        RegistryError::Cancelled => DescriptorError::Cancelled,
        RegistryError::Image(reason) => DescriptorError::Image(reason),
    }
}

fn read_parameter(image: &ExecutableView, va: u64) -> Result<[u8; 16], DescriptorError> {
    let bytes = image
        .read_va(va, 16)
        .map_err(|_| DescriptorError::MalformedParameter)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| DescriptorError::MalformedParameter)
}

/// Whether `[va, va + len)` lies inside one section's mapped span.
fn mapped_range(image: &ExecutableView, va: u64, len: u64) -> bool {
    let Some(rva) = image.va_to_rva(va) else {
        return false;
    };
    let Some(section) = image.section_at_rva(rva) else {
        return false;
    };
    let delta = rva - u64::from(section.virtual_address);
    delta
        .checked_add(len)
        .is_some_and(|end| end <= section.mapped_span())
}

fn code_sections(image: &ExecutableView) -> Vec<&Section> {
    image
        .sections()
        .iter()
        .filter(|section| {
            section.is_readable()
                && section.is_executable()
                && !section.is_writable()
                && section.raw_size != 0
        })
        .collect()
}

fn find_writer(
    image: &ExecutableView,
    sections: &[&Section],
    cancel: &AtomicBool,
) -> Result<u64, DescriptorError> {
    let mut hits = Vec::new();
    for section in sections {
        find_pattern(image, section, cancel, &mut hits)?;
    }
    let writers: Vec<u64> = hits
        .into_iter()
        .filter(|va| writer_semantics_ok(image, *va))
        .collect();
    match writers.as_slice() {
        [] => Err(DescriptorError::WriterNotFound),
        [writer] => Ok(*writer),
        _ => Err(DescriptorError::WriterAmbiguous),
    }
}

fn find_pattern(
    image: &ExecutableView,
    section: &Section,
    cancel: &AtomicBool,
    hits: &mut Vec<u64>,
) -> Result<(), DescriptorError> {
    let needle = &WRITER_PATTERN;
    let size = section.raw_size as usize;
    if size < needle.len() {
        return Ok(());
    }
    let base_rva = u64::from(section.virtual_address);
    let mut start = 0usize;
    while start + needle.len() <= size {
        if cancel.load(Ordering::Relaxed) {
            return Err(DescriptorError::Cancelled);
        }
        let window = (size - start).min(SEARCH_CHUNK);
        let read_len = (window + needle.len() - 1).min(size - start);
        let bytes = image
            .read_rva(base_rva + start as u64, read_len)
            .map_err(|_| DescriptorError::Image("a code section cannot be read"))?;
        for offset in 0..window {
            if offset + needle.len() > read_len {
                break;
            }
            if &bytes[offset..offset + needle.len()] == needle {
                hits.push(image.image_base() + base_rva + (start + offset) as u64);
                if hits.len() > MAX_WRITER_HITS {
                    return Err(resource(
                        "descriptor writer candidates",
                        MAX_WRITER_HITS as u64,
                    ));
                }
            }
        }
        start += SEARCH_CHUNK;
    }
    Ok(())
}

fn writer_semantics_ok(image: &ExecutableView, va: u64) -> bool {
    let Ok(bytes) = image.read_va(va, WRITER_PATTERN.len()) else {
        return false;
    };
    if bytes != WRITER_PATTERN {
        return false;
    }
    let Some(instructions) = decode_exact(&bytes, va) else {
        return false;
    };
    let mut key_store = false;
    let mut kind_store = false;
    let mut state_ops = 0;
    for instruction in &instructions {
        if memory_at(instruction, 0, Register::RCX, 0, MemorySize::UInt32)
            && instruction.op1_kind() == OpKind::Register
            && instruction.op1_register() == Register::EDX
        {
            key_store = true;
        }
        if memory_at(instruction, 0, Register::RCX, 4, MemorySize::UInt16)
            && instruction.op1_kind() == OpKind::Register
            && instruction.op1_register() == Register::R8W
        {
            kind_store = true;
        }
        if memory_at(
            instruction,
            0,
            Register::RCX,
            6,
            MemorySize::Packed128_Float32,
        ) || memory_at(
            instruction,
            1,
            Register::RCX,
            6,
            MemorySize::Packed128_Float32,
        ) {
            state_ops += 1;
        }
    }
    key_store && kind_store && state_ops >= 2
}

fn decode_exact(bytes: &[u8], ip: u64) -> Option<Vec<Instruction>> {
    let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
    let mut instructions = Vec::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return None;
        }
        instructions.push(instruction);
        if instruction.flow_control() == FlowControl::Return {
            break;
        }
        if instructions.len() > 16 {
            return None;
        }
    }
    if instructions.is_empty() || instructions.len() > 16 {
        return None;
    }
    let length: usize = instructions.iter().map(Instruction::len).sum();
    if length != bytes.len() {
        return None;
    }
    (instructions.last()?.flow_control() == FlowControl::Return).then_some(instructions)
}

fn memory_at(
    instruction: &Instruction,
    operand: u32,
    base: Register,
    displacement: u64,
    size: MemorySize,
) -> bool {
    instruction.op_kind(operand) == OpKind::Memory
        && instruction.memory_base() == base
        && instruction.memory_index() == Register::None
        && instruction.memory_displacement64() == displacement
        && instruction.memory_size() == size
}

fn find_call_sites(
    image: &ExecutableView,
    sections: &[&Section],
    writer: u64,
    cancel: &AtomicBool,
) -> Result<Vec<u64>, DescriptorError> {
    let mut sites = Vec::new();
    for section in sections {
        find_calls_in(image, section, writer, cancel, &mut sites)?;
        if sites.len() > MAX_CALL_SITES {
            return Err(resource(
                "descriptor writer call sites",
                MAX_CALL_SITES as u64,
            ));
        }
    }
    Ok(sites)
}

fn find_calls_in(
    image: &ExecutableView,
    section: &Section,
    writer: u64,
    cancel: &AtomicBool,
    sites: &mut Vec<u64>,
) -> Result<(), DescriptorError> {
    const CALL_LEN: usize = 5;
    let size = section.raw_size as usize;
    if size < CALL_LEN {
        return Ok(());
    }
    let base_rva = u64::from(section.virtual_address);
    let section_va = image.image_base() + base_rva;
    let mut start = 0usize;
    while start + CALL_LEN <= size {
        if cancel.load(Ordering::Relaxed) {
            return Err(DescriptorError::Cancelled);
        }
        let window = (size - start).min(SEARCH_CHUNK);
        let read_len = (window + CALL_LEN - 1).min(size - start);
        let bytes = image
            .read_rva(base_rva + start as u64, read_len)
            .map_err(|_| DescriptorError::Image("a code section cannot be read"))?;
        for offset in 0..window {
            if offset + CALL_LEN > read_len {
                break;
            }
            if bytes[offset] != 0xE8 {
                continue;
            }
            let displacement = i32::from_le_bytes([
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
            ]);
            let va = section_va + (start + offset) as u64;
            if (va as i64)
                .wrapping_add(CALL_LEN as i64)
                .wrapping_add(i64::from(displacement))
                != writer as i64
            {
                continue;
            }
            if direct_call_to(image, va, writer) {
                sites.push(va);
                if sites.len() > MAX_CALL_SITES {
                    return Err(resource(
                        "descriptor writer call sites",
                        MAX_CALL_SITES as u64,
                    ));
                }
            }
        }
        start += SEARCH_CHUNK;
    }
    Ok(())
}

fn direct_call_to(image: &ExecutableView, va: u64, writer: u64) -> bool {
    let Ok(bytes) = image.read_va(va, 5) else {
        return false;
    };
    let mut decoder = Decoder::with_ip(64, &bytes, va, DecoderOptions::NONE);
    let instruction = decoder.decode();
    instruction.flow_control() == FlowControl::Call
        && instruction.op0_kind() == OpKind::NearBranch64
        && instruction.near_branch_target() == writer
}

fn exception_functions(image: &ExecutableView) -> Result<Vec<(u64, u64)>, DescriptorError> {
    let Some(directory) = image.data_directory(lforge_binary::pe::DIRECTORY_EXCEPTION) else {
        return Err(unsupported("the executable has no exception table"));
    };
    let length = directory.end - directory.start;
    if length == 0 || !length.is_multiple_of(RUNTIME_FUNCTION_LEN as u64) {
        return Err(unsupported(
            "the exception table size is not a multiple of one entry",
        ));
    }
    if length > MAX_EXCEPTION_BYTES {
        return Err(resource("exception table", MAX_EXCEPTION_BYTES));
    }
    let length = usize::try_from(length)
        .map_err(|_| unsupported("the exception table is too large for this platform"))?;
    let bytes = image
        .read_rva(directory.start, length)
        .map_err(|_| unsupported("the exception table is not file-backed"))?;

    let mut functions = Vec::new();
    for entry in bytes.as_chunks::<RUNTIME_FUNCTION_LEN>().0 {
        let begin = u32::from_le_bytes(entry[0..4].try_into().expect("entry"));
        let end = u32::from_le_bytes(entry[4..8].try_into().expect("entry"));
        if begin == 0 && end == 0 {
            continue;
        }
        if begin >= end || u64::from(end) > u64::from(image.size_of_image()) {
            return Err(unsupported(
                "the exception table contains a malformed range",
            ));
        }
        functions.push((
            image.image_base() + u64::from(begin),
            image.image_base() + u64::from(end),
        ));
    }
    if functions.is_empty() {
        return Err(unsupported("the exception table is empty"));
    }
    Ok(functions)
}

fn containing_function(
    functions: &[(u64, u64)],
    va: u64,
) -> Result<Option<(u64, u64)>, DescriptorError> {
    let mut matches = functions
        .iter()
        .filter(|(start, end)| *start <= va && va < *end);
    match (matches.next(), matches.next()) {
        (None, _) => Ok(None),
        (Some(function), None) => Ok(Some(*function)),
        (Some(_), Some(_)) => Err(unsupported("ambiguous function bounds")),
    }
}

fn decode_function(
    image: &ExecutableView,
    start: u64,
    end: u64,
    cancel: &AtomicBool,
    limits: &Limits,
) -> Result<Vec<Insn>, DescriptorError> {
    let length = end - start;
    if length > limits.function_bytes as u64 {
        return Err(resource("function length", limits.function_bytes as u64));
    }
    let length = usize::try_from(length)
        .map_err(|_| unsupported("a function is too large for this platform"))?;
    let rva = image
        .va_to_rva(start)
        .ok_or(unsupported("a function lies below the image base"))?;
    let bytes = image
        .read_rva(rva, length)
        .map_err(|_| unsupported("a function is not file-backed"))?;

    let mut decoder = Decoder::with_ip(64, &bytes, start, DecoderOptions::NONE);
    let mut instructions = Vec::new();
    while decoder.can_decode() {
        if instructions.len() >= limits.function_instructions {
            return Err(resource(
                "function instructions",
                limits.function_instructions as u64,
            ));
        }
        if instructions.len().is_multiple_of(CANCEL_CHECK_INSTRUCTIONS)
            && cancel.load(Ordering::Relaxed)
        {
            return Err(DescriptorError::Cancelled);
        }
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return Err(unsupported(
                "a function contains an undecodable instruction",
            ));
        }
        instructions.push(Insn::new(&instruction));
    }
    if instructions.is_empty() {
        return Err(unsupported("a function contains no instructions"));
    }
    Ok(instructions)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Other,
    /// A comparison of a selector register with an immediate.
    Index(u64),
    /// A store of the key identifier into `edx`.
    Key(u32),
    /// A store of the cipher type into `r8w`.
    CipherType(u16),
    /// A `lea` of the parameter into `r9`.
    Parameter(u64),
    /// A `lea` of the descriptor object into `rcx`.
    Object(u64),
}

#[derive(Clone, Copy)]
struct Insn {
    addr: u64,
    next: u64,
    flow: FlowControl,
    target: Option<u64>,
    mnemonic: Mnemonic,
    kind: Kind,
}

impl Insn {
    fn new(instruction: &Instruction) -> Self {
        let addr = instruction.ip();
        let target = matches!(
            instruction.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        )
        .then(|| instruction.near_branch_target());
        Self {
            addr,
            next: addr + instruction.len() as u64,
            flow: instruction.flow_control(),
            target,
            mnemonic: instruction.mnemonic(),
            kind: classify(instruction),
        }
    }
}

fn classify(instruction: &Instruction) -> Kind {
    let mnemonic = instruction.mnemonic();
    if mnemonic == Mnemonic::Cmp
        && instruction.op0_kind() == OpKind::Register
        && matches!(
            instruction.op0_register(),
            Register::CL | Register::ECX | Register::EAX
        )
        && let Some(value) = immediate(instruction, 1)
        && value >= 0
    {
        return Kind::Index(value as u64);
    }
    if mnemonic == Mnemonic::Mov && instruction.op0_kind() == OpKind::Register {
        let register = instruction.op0_register();
        if let Some(value) = immediate(instruction, 1) {
            match register {
                Register::EDX if (0..=u32::MAX as i64).contains(&value) => {
                    return Kind::Key(value as u32);
                }
                Register::R8W if (0..=u16::MAX as i64).contains(&value) => {
                    return Kind::CipherType(value as u16);
                }
                _ => {}
            }
        }
    }
    if mnemonic == Mnemonic::Lea
        && instruction.op0_kind() == OpKind::Register
        && instruction.op1_kind() == OpKind::Memory
        && instruction.memory_base() == Register::RIP
        && instruction.memory_index() == Register::None
    {
        let target = instruction.memory_displacement64();
        match instruction.op0_register() {
            Register::R9 => return Kind::Parameter(target),
            Register::RCX => return Kind::Object(target),
            _ => {}
        }
    }
    Kind::Other
}

fn immediate(instruction: &Instruction, operand: u32) -> Option<i64> {
    Some(match instruction.op_kind(operand) {
        OpKind::Immediate8 | OpKind::Immediate8to16 | OpKind::Immediate8to32 => {
            i64::from(instruction.immediate8to32())
        }
        OpKind::Immediate8to64 => instruction.immediate8to64(),
        OpKind::Immediate16 => i64::from(instruction.immediate16()),
        OpKind::Immediate32 => i64::from(instruction.immediate32()),
        OpKind::Immediate32to64 => instruction.immediate32to64(),
        OpKind::Immediate64 => instruction.immediate64() as i64,
        _ => return None,
    })
}

#[derive(Clone, Copy)]
struct Tuple {
    block: usize,
    key_id: u32,
    kind: u16,
    parameter_va: u64,
    object_va: u64,
}

struct Found {
    index: u64,
    tuple: Tuple,
}

struct Blocks {
    insns: Vec<Insn>,
    /// Instruction index where each block starts.
    starts: Vec<usize>,
    /// Instruction index after each block.
    ends: Vec<usize>,
    successors: Vec<Vec<usize>>,
    /// Block of each instruction.
    block_of: Vec<usize>,
    index_of: HashMap<u64, usize>,
}

impl Blocks {
    fn build(insns: &[Insn]) -> Result<Self, DescriptorError> {
        if insns.is_empty() {
            return Err(unsupported("a function contains no instructions"));
        }
        let index_of: HashMap<u64, usize> = insns
            .iter()
            .enumerate()
            .map(|(index, insn)| (insn.addr, index))
            .collect();
        let mut leader = vec![false; insns.len()];
        leader[0] = true;
        for (index, insn) in insns.iter().enumerate() {
            let next = Some(index + 1).filter(|next| *next < insns.len());
            match insn.flow {
                FlowControl::ConditionalBranch => {
                    if let Some(target) = insn.target
                        && let Some(target) = index_of.get(&target)
                    {
                        leader[*target] = true;
                    }
                    if let Some(next) = next {
                        leader[next] = true;
                    }
                }
                FlowControl::UnconditionalBranch => {
                    if let Some(target) = insn.target
                        && let Some(target) = index_of.get(&target)
                    {
                        leader[*target] = true;
                    }
                }
                FlowControl::Return => {
                    if let Some(next) = next {
                        leader[next] = true;
                    }
                }
                _ => {}
            }
        }

        let starts: Vec<usize> = (0..insns.len()).filter(|index| leader[*index]).collect();
        let mut ends = starts.clone();
        ends.rotate_left(1);
        *ends.last_mut().expect("non-empty") = insns.len();

        let mut block_of = vec![0usize; insns.len()];
        for (block, (start, end)) in starts.iter().zip(&ends).enumerate() {
            block_of[*start..*end].fill(block);
        }

        let mut successors = Vec::with_capacity(starts.len());
        for end in &ends {
            let last = &insns[end - 1];
            let mut next_blocks = Vec::new();
            let mut push = |address: u64| {
                if let Some(index) = index_of.get(&address) {
                    let target = block_of[*index];
                    if !next_blocks.contains(&target) {
                        next_blocks.push(target);
                    }
                }
            };
            match last.flow {
                FlowControl::UnconditionalBranch => {
                    if let Some(target) = last.target {
                        push(target);
                    }
                }
                FlowControl::ConditionalBranch => {
                    if let Some(target) = last.target {
                        push(target);
                    }
                    push(last.next);
                }
                FlowControl::Call | FlowControl::IndirectCall | FlowControl::Next => {
                    if *end < insns.len() {
                        push(last.next);
                    }
                }
                FlowControl::Return
                | FlowControl::IndirectBranch
                | FlowControl::Interrupt
                | FlowControl::Exception
                | FlowControl::XbeginXabortXend => {}
            }
            drop(push);
            successors.push(next_blocks);
        }

        Ok(Self {
            insns: insns.to_vec(),
            starts,
            ends,
            successors,
            block_of,
            index_of,
        })
    }

    fn block_of_address(&self, address: u64) -> Option<usize> {
        self.index_of
            .get(&address)
            .map(|index| self.block_of[*index])
    }

    /// Descriptor paths that jump to `call_block`. The last assignment of each
    /// value in a block wins, as in the research prototype.
    fn descriptor_tuples(&self, call_block: usize) -> Vec<Tuple> {
        let mut tuples = Vec::new();
        for block in 0..self.starts.len() {
            if !self.successors[block].contains(&call_block) {
                continue;
            }
            let (mut key, mut kind, mut parameter, mut object) = (None, None, None, None);
            for insn in &self.insns[self.starts[block]..self.ends[block]] {
                match insn.kind {
                    Kind::Key(value) => key = Some(value),
                    Kind::CipherType(value) => kind = Some(value),
                    Kind::Parameter(value) => parameter = Some(value),
                    Kind::Object(value) => object = Some(value),
                    Kind::Other | Kind::Index(_) => {}
                }
            }
            if let (Some(key_id), Some(kind), Some(parameter_va), Some(object_va)) =
                (key, kind, parameter, object)
            {
                tuples.push(Tuple {
                    block,
                    key_id,
                    kind,
                    parameter_va,
                    object_va,
                });
            }
        }
        tuples
    }

    /// Selector indices whose equality test reaches `tuple_block`.
    fn indices_for(&self, tuple_block: usize) -> Vec<u64> {
        let mut indices = Vec::new();
        for (position, insn) in self.insns.iter().enumerate() {
            let Kind::Index(value) = insn.kind else {
                continue;
            };
            let mut equal = None;
            for next in self.insns.iter().skip(position + 1).take(BRANCH_LOOKAHEAD) {
                match next.flow {
                    FlowControl::ConditionalBranch => {
                        equal = match next.mnemonic {
                            Mnemonic::Je => next.target,
                            Mnemonic::Jne => Some(next.next),
                            _ => None,
                        };
                        break;
                    }
                    FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => break,
                    _ => {}
                }
            }
            let Some(equal) = equal else {
                continue;
            };
            let Some(start) = self.index_of.get(&equal) else {
                continue;
            };
            let source = self.block_of[*start];
            if !indices.contains(&value) && self.reachable(source, tuple_block) {
                indices.push(value);
            }
        }
        indices
    }

    fn reachable(&self, source: usize, target: usize) -> bool {
        if source == target {
            return true;
        }
        let mut seen = HashSet::new();
        let mut queue = VecDeque::new();
        seen.insert(source);
        queue.push_back(source);
        while let Some(block) = queue.pop_front() {
            if block == target {
                return true;
            }
            if seen.len() > REACHABLE_LIMIT {
                return false;
            }
            for &next in &self.successors[block] {
                if seen.insert(next) {
                    queue.push_back(next);
                }
            }
        }
        false
    }
}
