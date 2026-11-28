# Manual acceptance: drawable dictionaries, fragments and skeletons

This page lists the resources and expected results to check the model features by
hand. It is written for the maintainer: every resource is named by the canonical
path the application itself shows, and the native row chain follows in
parentheses as the technical fallback.

## Build and launch

| Item               | Value                                                                                                         |
| ------------------ | ------------------------------------------------------------------------------------------------------------- |
| Release executable | `target\release\leonida-forge.exe` under the repository root                                                 |
| Game root          | `D:\GTA VI` (read only)                                                                                       |
| Texture stores     | `D:\GTA VI\data\ttdb`                                                                                         |

Build it with `cargo build --release -p lforge-desktop`; the binary is the
`leonida-forge` target, not the `lforge` command-line tool beside it.

Launch the executable, set the game root when asked, then open the root archive
listed for a resource and descend into the nested archives it names.

## How a resource is named

Every resource below is given by its canonical path, which is the string the
application itself shows: the **Resource path** line of the window and of the
inspector. It is the root file name, then the stored entry name of each archive
on the way down, separated by `!`. A component the name index resolves is a
relative path such as `levels/americas/props/furniture/am_ornaments.rpf`; a
component it does not resolve stays the stored key, such as
`0x0781E13426B493CF.zft`.

The row chain is the same resource in native row numbers,
`<archive>!<row>!<row>`. Every intermediate row is a nested RPF9 archive declared
type 0. The chains are the fallback for a reader holding only a table of
contents, and they are what the automated harnesses use.

Beside the path, each window prints a **Resource identity** line: the same chain
with every component spelled `hash64:0x…` (64-bit key) or `key32:0x…` (32-bit
key) instead of a name. The identity is what decides whether two paths name the
same entry, so it is the line to compare if a name ever looks wrong.

| Resource              | Canonical path                                                                          | Row chain                                        | Type |
| --------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------ | ---- |
| Tarot deck            | `levels.rpf!levels/americas/props/furniture/am_ornaments.rpf!0x00F3FFFF0AB33AD1.zft`     | `levels.rpf!5!0`                                 | 3    |
| Candlestick           | `levels.rpf!levels/americas/props/furniture/am_ornaments.rpf!0x018C79492CD36803.zft`     | `levels.rpf!5!1`                                 | 3    |
| Peacock taxidermy     | `levels.rpf!levels/americas/props/furniture/am_ornaments.rpf!0x0781E13426B493CF.zft`     | `levels.rpf!5!8`                                 | 3    |
| Fish trophy           | `levels.rpf!levels/americas/props/furniture/am_ornaments.rpf!0xC85CCB1C0FC2F172.zdr`     | `levels.rpf!5!252`                               | 2    |
| Weapon bolt           | `data.rpf!0x98531060A2A91C59.rpf!0x00C111CBBAA1A730.zft`                                | `data.rpf!26!9`                                  | 3    |
| Dominator9            | `levels.rpf!0x02CFAA745D57428E.rpf!0x072F7B96A28A3A97.zft`                              | `levels.rpf!21!85`                               | 3    |
| Rabbit                | `packs.rpf!0x7966580C5FE53CBD.rpf!0x006B6DFC5EEB3E19.zft`                               | `packs.rpf!26!0`                                 | 3    |
| Ambient female body   | `packs.rpf!0x7966580C5FE53CBD.rpf!0xC9888B65009B33B7.zft`                               | `packs.rpf!26!255`                               | 3    |
| Tow cable             | `levels.rpf!0x9FE32804F90C0083.rpf!0x444AD46F47782C34.zft`                              | `levels.rpf!1240!14`                             | 3    |
| Bowtie dictionary     | `packs.rpf!0x436BC7C5DE075758.rpf!0x03DFE5C59D87AD52.zdd`                               | `packs.rpf!9!5`                                  | 4    |
| Four-member dictionary | `data.rpf!0x3C114BBB8762BF75.rpf!0x431780D43EF7212A.zdd`                               | `data.rpf!7!0`                                   | 4    |
| Thirteen-member dictionary | `core_restofworld.rpf!0xD21145C64ADDC0C8.rpf!0xA88ED48FAFB24C23.zdd`                | `pack/core_restofworld/core_restofworld.rpf!6!0` | 4    |
| Eighty-three-member dictionary | `data.rpf!0xD21145C64ADDC0C8.rpf!0xC6B6835BA02FDFAD.zdd`                          | `data.rpf!31!6`                                  | 4    |
| One-hundred-and-eight-member dictionary | `data.rpf!0xD21145C64ADDC0C8.rpf!0xF073FD9111A4FB6E.zdd`                     | `data.rpf!31!8`                                  | 4    |
| Texture dictionary    | `data.rpf!0x06D66D6DB5BFA8C1.rpf!0x017D774086E5C6BE.ztd`                                | `data.rpf!1!0`                                   | 5    |
| PSIN metadata sample  | `data.rpf!0x006DD6C9.zmt`                                                               | `data.rpf!41`                                    | 11   |
| RBF0 metadata sample  | `data.rpf!data/ui/loose/helpDataset_core.zmt`                                            | `data.rpf!100`                                   | 11   |

To reach a resource, open the root archive named first, then descend through the
components in order. Components that are names are folders and archive files in
the explorer; components that are stored keys are the labels of the rows that
hold them. Nested archives list every row flat, so a key after them is one entry
in that list. A top-level archive groups its rows into the folders a verified
relative path describes, and lists every other row under `Unnamed Entries`; a
key that stands alone after the root, such as `0x006DD6C9.zmt`, is one of those
unnamed rows. A path such as `data/ui/loose/helpDataset_core.zmt` is three
folders down from the root.

## Drawable dictionaries

All four are declared type 4 (`zdd`) and open in the **drawable dictionary
viewer**: a member list plus a viewport for the selected member.

| Dictionary            | Canonical path                                                    | Row chain                                        | Type | Members | Page map  | First member                            |
| --------------------- | ----------------------------------------------------------------- | ------------------------------------------------ | ---- | ------: | --------- | --------------------------------------- |
| Four members          | `data.rpf!0x3C114BBB8762BF75.rpf!0x431780D43EF7212A.zdd`           | `data.rpf!7!0`                                   | 4 (`zdd`) |       4 | `0x5f70`  | `farlod_structures_01.#dr`              |
| Thirteen members      | `core_restofworld.rpf!0xD21145C64ADDC0C8.rpf!0xA88ED48FAFB24C23.zdd` | `pack/core_restofworld/core_restofworld.rpf!6!0` | 4 (`zdd`) |      13 | `0x7860`  | `ptfx_model_gore_bone_02.#dr`           |
| Eighty-three members  | `data.rpf!0xD21145C64ADDC0C8.rpf!0xC6B6835BA02FDFAD.zdd`           | `data.rpf!31!6`                                  | 4 (`zdd`) |      83 | `0x314e0` | `ptfx_model_leaf_palm_01.#dr`           |
| One hundred and eight | `data.rpf!0xD21145C64ADDC0C8.rpf!0xF073FD9111A4FB6E.zdd`           | `data.rpf!31!8`                                  | 4 (`zdd`) |     108 | `0x3f810` | `ptfx_model_debris_glass_bottle_01.#dr` |

Expected for every member row: a name, a name hash, and the state `drawable`.
A member that fails to decode shows its reason instead of a scene, and the other
members stay usable.

Expected for the first member of each dictionary, decoded with the shared
texture stores:

| Dictionary            | Vertices | Triangles | Meshes | Materials | Bindings (resolved) | Geometry | Textures                             |
| --------------------- | -------: | --------: | -----: | --------: | ------------------: | -------- | ------------------------------------ |
| Four                  |   15,794 |    19,079 |      1 |         1 |               0 (0) | Complete | NotReferenced                        |
| Thirteen              |      254 |       375 |      1 |         1 |               4 (2) | Complete | Partial (1 material uses a fallback) |
| Eighty-three          |       34 |        32 |      1 |         1 |               4 (3) | Complete | Partial (1 material uses a fallback) |
| One hundred and eight |      229 |       198 |      1 |         1 |               4 (2) | Complete | Partial (1 material uses a fallback) |

The missing textures are absent from the shared store, not from the resource:
the diagnostics name each unresolved reference.

Switch rapidly between members. At most one member load runs at a time and at
most one selection waits behind it, so the viewer shows the last member selected
and never an earlier one.

## Fragments

All are declared type 3 (`zft`) and open in the **model viewer** with a component
panel. Each holds one component, and the panel's header reads
`DRAWABLE CONTENTS · 1 COMPONENT(S) · N MESH(ES)`.

| Fragment          | Canonical path                                                                       | Row chain         | Type | Member drawable                   | Split    | Component            | Scene                                                                                  |
| ----------------- | ------------------------------------------------------------------------------------ | ----------------- | ---- | --------------------------------- | -------- | -------------------- | -------------------------------------------------------------------------------------- |
| Tarot deck        | `levels.rpf!levels/americas/props/furniture/am_ornaments.rpf!0x00F3FFFF0AB33AD1.zft`   | `levels.rpf!5!0`  | 3 (`zft`) | `prop_am_card_tarot_deck_01a.#ft` | `0x1980` | 1 mesh, 1 primitive  | 88 vertices, 76 triangles, 1 material, 3 textures, 4 bindings (3 resolved)             |
| Candlestick       | `levels.rpf!levels/americas/props/furniture/am_ornaments.rpf!0x018C79492CD36803.zft`   | `levels.rpf!5!1`  | 3 (`zft`) | `prop_am_candlestick_02a.#ft`     | `0x3cc0` | 1 mesh, 2 primitives | 927 vertices, 1,232 triangles, 2 materials, 6 textures, 10 bindings (10 resolved)      |
| Weapon bolt       | `data.rpf!0x98531060A2A91C59.rpf!0x00C111CBBAA1A730.zft`                              | `data.rpf!26!9`   | 3 (`zft`) | `w_sg_goodwin_01_bolt_01_mid.#ft` | `0x1c30` | 1 mesh, 1 primitive  | 620 vertices, 372 triangles, 1 material, 3 textures, 4 bindings (3 resolved)           |
| Peacock taxidermy | `levels.rpf!levels/americas/props/furniture/am_ornaments.rpf!0x0781E13426B493CF.zft`   | `levels.rpf!5!8`  | 3 (`zft`) | `mint_peacock_taxidermy_01.#ft`   | `0xbbc0` | 1 mesh, 4 primitives | 41,613 vertices, 45,132 triangles, 4 materials, 16 textures, 19 bindings (16 resolved) |

Expected completeness for all four: geometry `Complete`, and textures `Complete`
when every binding resolves, `Partial` with the count of materials that fall back
otherwise. Each fragment root reports `3 unexplained root pointer(s)`, which is
the documented state of the three root slots whose meaning is not established;
the panel lists them as such and does not invent components for them.

The peacock is the regression sample for the classification rule: its root also
reads as a resource-level drawable, so the member name decides and the note
`the root also reads as a resource-level drawable; the member name selected the
fragment interpretation` appears with the model notes.

## Skeletons

A drawable whose header carries a skeleton shows a **Skeleton** section with a
`skeleton-toggle`, a `bone-hierarchy` list, a filter field (placeholder
`Filter bones, indices, keys`) and a `bone-metadata` list. The overlay stays off
until the toggle is pressed, and pressing it re-reads no resource.

| Resource          | Canonical path                                                                     | Row chain          | Type | Member drawable                   | Bones | Roots | Depth |
| ----------------- | ---------------------------------------------------------------------------------- | ------------------ | ---- | --------------------------------- | ----: | ----: | ----: |
| Tarot deck        | `levels.rpf!levels/americas/props/furniture/am_ornaments.rpf!0x00F3FFFF0AB33AD1.zft` | `levels.rpf!5!0`   | 3 (`zft`) | `prop_am_card_tarot_deck_01a.#ft` |     3 |     1 |     3 |
| Weapon bolt       | `data.rpf!0x98531060A2A91C59.rpf!0x00C111CBBAA1A730.zft`                            | `data.rpf!26!9`    | 3 (`zft`) | `w_sg_goodwin_01_bolt_01_mid.#ft` |     3 |     1 |     3 |
| Candlestick       | `levels.rpf!levels/americas/props/furniture/am_ornaments.rpf!0x018C79492CD36803.zft` | `levels.rpf!5!1`   | 3 (`zft`) | `prop_am_candlestick_02a.#ft`     |     4 |     1 |     4 |
| Peacock taxidermy | `levels.rpf!levels/americas/props/furniture/am_ornaments.rpf!0x0781E13426B493CF.zft` | `levels.rpf!5!8`   | 3 (`zft`) | `mint_peacock_taxidermy_01.#ft`   |    10 |     1 |    10 |
| Dominator model   | `levels.rpf!0x02CFAA745D57428E.rpf!0x072F7B96A28A3A97.zft`                          | `levels.rpf!21!85` | 3 (`zft`) | `dominator9_hi.#ft`               |   386 |     1 |    19 |
| Many roots        | `packs.rpf!0x7966580C5FE53CBD.rpf!0x006B6DFC5EEB3E19.zft`                            | `packs.rpf!26!0`   | 3 (`zft`) | `crm_rabbit_marsh_m_00.#ft`       |    98 |    10 |    15 |
| Largest in the census | `packs.rpf!0x7966580C5FE53CBD.rpf!0xC9888B65009B33B7.zft`                        | `packs.rpf!26!255` | 3 (`zft`) | `ambient_femalebody.#ft`          |   596 |    16 |    24 |

The four small fragments report `complete` associations. Their vertex space is
reported as `authored geometry matches bounds` for the candlestick (2 of 2 boxes)
and the peacock (4 of 4); the tarot and bolt records declare no per-geometry box,
so they report `unverified`. The dominator sample declares boxes for all 37 of
its geometries and they match, worst delta `7.4e-5`, but its associations are
`partial`, so its placement line stays `unverified` and names the association.
The two large pack resources declare no box, so no panel line names their space.

The largest resource is a fragment, not a dictionary member: its row is declared
type 3 (`zft`), and the notice names the member drawable `ambient_femalebody.#ft`
whose skeleton it holds. It is the sample for reaching bones past the old row
caps: filter a leaf name and the 596 rows scroll to it.

## Posing a skeleton

A resource whose influences decode shows a **POSE** section under the skeleton
list. Its header reads `N of M primitive(s) deform; K bone(s)` and then
`reference pose` or `edited pose`; an inferred association adds
`(I inferred single-bone excluded)` or `included`. `Pose Mode` enters the session.
The section then
offers `authored` and `posed`, `Influence View`, six rotation buttons, six
translation buttons, `Reset Bone` and `Reset Pose`.

Conventions, the same in the CPU reference, the shader and the buttons:

- A rotation button adds 5 degrees about the named axis **of the bone's own
  space**, applied after the stored local rotation. It is not a model-space or
  parent-space axis.
- A translation button adds 0.05 m along the named axis **in the parent's
  space**, the space the stored local translation lives in.
- Euler order for the three buttons is XYZ, and each angle wraps to
  `-180..180`.
- Scale is not offered. A bone with non-identity scale is refused, not
  approximated.
- Nothing is persisted: closing the window discards the pose.

The release executable is
`E:\source\leonidaforge\worktrees\vertex-influences-skinning\leonida-forge\target\release\leonida-forge.exe`.

None of the five verified poses below changes under the new default: every one of
them is a decoded association. The inferred class has its own section after the
weighted cases.

### Peacock, weighted deformation

`levels.rpf!levels/americas/props/furniture/am_ornaments.rpf!0x0781E13426B493CF.zft`
(row chain `levels.rpf!5!8`), declared type 3,
`mint_peacock_taxidermy_01.#ft`. Ten bones, one root, depth 10, four primitives,
41,613 vertices, all four deformable.

| Step | Expected |
| ---- | -------- |
| Press `Pose Mode` | `4 of 4 primitive(s) deform; 10 bone(s)`, `reference pose`, mesh unchanged |
| Select `Tail_01` (index 4), press `Rotate Z+` eight times | bone line reads `0 0 40`, label `edited pose`, tail fans out; worst vertex displacement 1.19 m |
| Count the moved geometry | 31,480 of 41,613 vertices move. Primitive 0 (2,685 vertices, one bone) does not move; primitive 3 (25,456 vertices, seven bones) moves 24,496 of them; the pedestal, legs and floor stay |
| Press `Influence View` | tail shaded orange to yellow by weight (0.906 and 0.094 on the first vertex), unweighted geometry neutral grey, display switches to `posed` |
| Select a bone no vertex references, for example `bone 9` | the influence view shows no highlighted geometry; the section still reads `edited pose` |
| Press `authored` | authored mesh returns, skeleton overlay keeps the edited pose, label `edited pose` |
| Press `posed` | the deformation returns |
| Press `Reset Bone` | tail returns to reference, label `reference pose` |
| Press `Reset Pose` | every delta clears, label `reference pose` |
| Press `Reset View` after a large rotation | camera frames the deformed geometry, not the authored one |
| Press `Exit Pose` | authored mesh and reference skeleton return; the section keeps only its header |
| Press `Pose Mode` again | `reference pose`: the discarded pose does not come back |

### Candlestick, single-influence deformation

`levels.rpf!levels/americas/props/furniture/am_ornaments.rpf!0x018C79492CD36803.zft`
(row chain `levels.rpf!5!1`), declared type 3, `prop_am_candlestick_02a.#ft`.
Four bones, one root, two primitives, 927 vertices, both deformable, both
single-influence, both whole-primitive rigid.

| Step | Expected |
| ---- | -------- |
| Press `Pose Mode`, select `Candle` (index 3), press `Rotate Z+` twelve times | bone line reads `0 0 60` |
| Count the moved geometry | 139 of 927 vertices move, by at most 0.0182 m; the 139-vertex primitive is bound to `Candle` and turns as one piece |
| Check the other primitive | the 788-vertex primitive is bound to bone 2 and does not move at all |
| Press `Reset Bone` | both primitives return to the authored shape |

The earlier acceptance page called all 788 vertices affected. That was the
primitive's size, not the moved count; the measurement above replaces it.

### Dominator9, partial support on a 386-bone skeleton

`levels.rpf!0x02CFAA745D57428E.rpf!0x072F7B96A28A3A97.zft` (row chain
`levels.rpf!21!85`), declared type 3, `dominator9_hi.#ft`. 386 bones, one root,
depth 19, three meshes and 37 primitives, of which 29 deform (91,466 vertices).
The eight that do not deform declare no usable influence attribute and stay on
the authored path. The highest active bone index is 385, one below the bone
count.

| Step | Expected |
| ---- | -------- |
| Press `Pose Mode` | `29 of 37 primitive(s) deform; 386 bone(s)` |
| Select `wing_rf` (index 372), press `Rotate Z+` five times | bone line reads `0 0 25` |
| Count the moved geometry | 2,077 vertices move: 1,840 of mesh 1 primitive 0 and 237 of mesh 1 primitive 4, worst 0.304 m |
| Check propagation | the only other moved bone is 372's child; the other 384 bones keep their transform |
| Press `Reset Bone` | every primitive returns to the authored shape |

The bone name is reported, not interpreted: nothing here claims the part is a
door, a wheel or a suspension element.

### Large skeleton and multiple roots

| Resource | Canonical path | Skeleton | Step | Expected |
| -------- | -------------- | -------- | ---- | -------- |
| Ambient female body | `packs.rpf!0x7966580C5FE53CBD.rpf!0xC9888B65009B33B7.zft` (row chain `packs.rpf!26!255`), type 3, `ambient_femalebody.#ft` | 596 bones, 16 roots, depth 24 | `Pose Mode`, select `SKEL_ROOT` (index 0), `Rotate Z+` six times | `1 of 1 primitive(s) deform; 596 bone(s)`; 572 bones move and 24 do not, all 24 under the other 15 roots; the single 25-vertex primitive moves 9.15 m |
| Rabbit | `packs.rpf!0x7966580C5FE53CBD.rpf!0x006B6DFC5EEB3E19.zft` (row chain `packs.rpf!26!0`), type 3, `crm_rabbit_marsh_m_00.#ft` | 98 bones, 10 roots, depth 15 | `Pose Mode`, select `SKEL_ROOT` (index 0), `Rotate Z+` six times | 81 bones move, the 17 bones under the other nine roots keep their transforms, and the 25-vertex primitive moves 9.17 m |

Both resources are fragments whose decoded LOD-0 member drawable holds one
25-vertex primitive bound to the root bone, so they verify pose propagation and
root independence rather than weighted character skinning. The 596-bone skeleton
uploads and renders, which is what the matrix buffer has to carry; the geometry
does not exercise it. The weighted large-skeleton case is the dominator above.

### Inferred single-bone associations are opt-in

`levels.rpf!0x9FE32804F90C0083.rpf!0x444AD46F47782C34.zft` (row chain
`levels.rpf!1240!14`) is `coastguard_base_towcable.#ft`: one bone, one root, two
primitives and 150 vertices. Its declaration table is
`[0,1,2,3,4,11,12,13,14,15,17]`, so it stores a tangent stream and **no** weight or
index attribute. The two primitives are associated with the only bone by
inference.

| Step | Expected |
| ---- | -------- |
| Press `Pose Mode` | `0 of 2 primitive(s) deform (2 inferred single-bone excluded); 1 bone(s)` |
| Select `SKEL_ROOT` (index 0), press `Rotate Z+` six times | the mesh does not move; the label reads `edited pose` |
| Read the panel line under the toggle | `2 primitive(s) stay authored: their single-bone association is inferred, not verified` |
| Press `Single-bone excluded` | the toggle reads `Single-bone included`, the header reads `2 of 2 primitive(s) deform (2 inferred single-bone included)`, and the cable now follows the bone: 150 of 150 vertices move, worst 1.66 m |
| Press `Influence View` | the cable is shaded yellow at full weight, which is what an inferred single influence holds |
| Press `Single-bone included` again | the mesh returns to the authored pose and the header returns to `0 of 2` |
| Press `Reset Bone`, then `Exit Pose`, then `Pose Mode` | the reference pose each time, and the policy returns to excluded, because the session is new |

The same geometry is the declaration-parser sample for tangents: the old reader
stopped after slot 4 and never saw slot 11, so it decoded the mesh without
tangents. The posed render now matches the CPU-deformed reference to 1 pixel of
630,000.

### Weighted data the decoder rejects

`packs.rpf!0x436BC7C5DE075758.rpf!0x03DFE5C59D87AD52.zdd` (row chain
`packs.rpf!9!5`) is a one-member drawable dictionary; member 0 is
`neckwearbowtie_mr1_000_regular_t_un_high_full.#dr` with 69 bones, 69 roots and
one 125-vertex primitive with four influences on 12 bones. Its four stored
weights total 254 rather than 255 or 127, which are the two denominators the
format establishes, so the primitive is reported as unnormalised and is not
deformed. The four weights read 1.0000 because the decoder divides by the total
it observed; the status, not the sum, is what refuses the deformation.

| Step | Expected |
| ---- | -------- |
| Open the dictionary, select member 0 | skeleton section reads `69 BONE(S) · 69 ROOT(S) · DEPTH 1`; no POSE section appears |
| Read the diagnostics | one line names the unnormalised blend weights and the total it observed (254) |
| Toggle the skeleton | bones render at the reference pose; the mesh stays authored |

A dictionary member carries its own skeleton and its own viewport. Selecting a
different member replaces the viewport, and a new viewport starts with pose mode
off, so a pose cannot survive a member switch. This dictionary has one member,
so the replacement path is covered by the unit test of `Viewport` construction
and by the model viewer, not by switching inside this dictionary.

### Lifecycle checks

| Check | Expected |
| ----- | -------- |
| Hold a rotation button down on the peacock | the last step is what renders; no queued backlog, no growing delay, no reload |
| Change the selected bone repeatedly in the influence view | the colours follow the new bone without a resource reload or a geometry upload |
| Hide a mesh, pose, then exit pose mode | the mesh stays hidden; the camera is unchanged |
| Open two model windows and pose one | the other window keeps its own pose and camera |
| Close a window while posed | the render thread stops and the GPU buffers are released with it |

### Skeleton-free and unrelated resources

`levels.rpf!levels/americas/props/furniture/am_ornaments.rpf!0xC85CCB1C0FC2F172.zdr`
(row chain `levels.rpf!5!252`, `prop_am_trophy_fish_06a_batchlod.#dr`, type 2) has
no skeleton and shows no POSE section. Its default render is unchanged: 171
vertices, 158 triangles, one mesh, one material, five reconstructed texture
bindings, complete geometry and textures.

The drawable dictionaries `data.rpf!0x3C114BBB8762BF75.rpf!0x431780D43EF7212A.zdd`,
`data.rpf!0xD21145C64ADDC0C8.rpf!0xC6B6835BA02FDFAD.zdd`,
`data.rpf!0xD21145C64ADDC0C8.rpf!0xF073FD9111A4FB6E.zdd` and
`core_restofworld.rpf!0xD21145C64ADDC0C8.rpf!0xA88ED48FAFB24C23.zdd`, and the
texture dictionary `data.rpf!0x06D66D6DB5BFA8C1.rpf!0x017D774086E5C6BE.ztd` with
five records, are unchanged checks from the earlier acceptance runs.

## A dictionary member with a skeleton

`packs.rpf!0x436BC7C5DE075758.rpf!0x03DFE5C59D87AD52.zdd` (row chain
`packs.rpf!9!5`) is a drawable dictionary declared type 4 (`zdd`) with one member.
Member 0 is `neckwearbowtie_mr1_000_regular_t_un_high_full.#dr` with 69 bones,
69 roots, depth 1, `complete` associations and an `unverified` vertex space.

A dictionary member carries its own skeleton: selecting another member replaces
the bone list, the filter text, the collapse state and the selection, and a
member without a skeleton shows no Skeleton section. No dictionary among the 400
pack dictionaries read holds both a skeleton-bearing and a skeleton-free member,
so the skeleton-free side of that transition is checked by opening one of the
drawable dictionaries above (for example `data.rpf!7!0`) and confirming it has
no Skeleton section at all.

The maintainer accepted this behaviour by hand on revision `1e7100c`.

## A drawable that is not a fragment

`levels.rpf!levels/americas/props/furniture/am_ornaments.rpf!0xC85CCB1C0FC2F172.zdr`
(row chain `levels.rpf!5!252`) is declared type 2 (`zdr`) and opens in the **model
viewer** as a plain drawable: `prop_am_trophy_fish_06a_batchlod.#dr`, resource
`0x000043A010`, native split `0xb10`.

| Quantity  |                        Expected |
| --------- | ------------------------------: |
| Vertices  |                             171 |
| Triangles |                             158 |
| Meshes    |                               1 |
| Materials |                               1 |
| Bindings  | 5 (5 resolved, 5 reconstructed) |
| Geometry  |                        Complete |
| Textures  |                        Complete |

## A texture dictionary

`data.rpf!0x06D66D6DB5BFA8C1.rpf!0x017D774086E5C6BE.ztd` (row chain `data.rpf!1!0`)
is declared type 5 (`ztd`) and opens in the **texture dictionary viewer**: 5 hashes
of capacity 5, 5 records, allocation partition agrees.

## Metadata containers are unchanged

Two resources exercise the metadata viewer that the same build carries, which is
the check that the model work did not take over another format's rows. Both are
declared type 11 and neither starts with a drawable's magic, so the viewer choice
is decided by the payload, not by the type.

| Resource | Canonical path | Row chain | Expected |
| -------- | -------------- | --------- | -------- |
| PSIN container | `data.rpf!0x006DD6C9.zmt` | `data.rpf!41` | the **Metadata Viewer** opens; the title bar reads the canonical path; the status line ends `<count> hashes named`, and the tree starts at the schema |
| RBF0 document | `data.rpf!data/ui/loose/helpDataset_core.zmt` | `data.rpf!100` | the **Metadata Viewer** opens; the title bar reads the canonical path; the status line ends `15 names in the document` |
| A drawable row, for contrast | `levels.rpf!levels/americas/props/furniture/am_ornaments.rpf!0x0781E13426B493CF.zft` | `levels.rpf!5!8` | the **model viewer** opens, not the metadata or text viewer |

The drawable row in the third line is the peacock, so the two checks share one
walk through the explorer: if the peacock still opens as a model, the model
route is intact; if the two `.zmt` rows open as metadata, that route is intact
too.

## Correction to the previous handoff

The earlier selector list gave `levels.rpf!5!0` for the four-member dictionary.
That row is the tarot-deck fragment (`prop_am_card_tarot_deck_01a.#ft`). The
four-member dictionary is `data.rpf!0x3C114BBB8762BF75.rpf!0x431780D43EF7212A.zdd`
(row chain `data.rpf!7!0`), as listed above. Every other resource in this page
was re-resolved from the installation census and re-read in place.

The skeleton list once called `packs.rpf!26!255` a dictionary member. That row
is declared type 3 (`zft`), a fragment; the 596-bone member drawable is
`ambient_femalebody.#ft`, not a dictionary member.
`packs.rpf!0x436BC7C5DE075758.rpf!0x03DFE5C59D87AD52.zdd` (row chain
`packs.rpf!9!5`) is the dictionary, and it has one member rather than a member
list to switch through.

## Where the paths come from

Every canonical path on this page was produced by the explorer's own path model:
the harness `reports_canonical_resource_paths` in
`apps/desktop/src/files/canonical_paths.rs` resolves each row chain through
`files::list_with`, which is the function the explorer uses, and prints the
`Resource path`, the `Resource identity`, the declared type and the decoded
member name. Nothing here was typed by hand. The harness only reports; the
comparison with the window is the reader's.

Run it with:

```text
cargo test -p lforge-desktop --bin leonida-forge -- --ignored --nocapture reports_canonical_resource_paths
```

with `LF_PATH_CASES` naming a list of row chains, `LF_TEST_GAME_ROOT` the game
root and `LF_TEST_EXECUTABLE` the game executable.
