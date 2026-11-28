# Manual acceptance: drawable dictionaries, fragments and skeletons

This page lists the exact archives, rows and expected results to check the three
model features by hand. It is written for the maintainer, so every selector is
the original native path in the release installation, not a copy.

## Build and launch

| Item               | Value                                                                                                         |
| ------------------ | ------------------------------------------------------------------------------------------------------------- |
| Release executable | `target\release\leonida-forge.exe` under the repository root                                                 |
| Game root          | `D:\GTA VI` (read only)                                                                                       |
| Texture stores     | `D:\GTA VI\data\ttdb`                                                                                         |

Build it with `cargo build --release -p lforge-desktop`; the binary is the
`leonida-forge` target, not the `lforge` command-line tool beside it.

Launch the executable, set the game root when asked, then open the root archive
listed for a selector and descend into the nested archives it names.

## How a selector is written

`<archive>!<row>!<row>` means: open `<archive>` from the game root, descend into
the archive stored in that row, then open the row given last. Every intermediate
row is a nested RPF9 archive whose declared type is 0. Rows are the row indices
the explorer shows, which are the native table-of-contents indices.

## Drawable dictionaries

All four are declared type 4 (`zdd`) and open in the **drawable dictionary
viewer**: a member list plus a viewport for the selected member.

| Dictionary            | Native chain                                     | Declared type | Members | Page map  | First member                            |
| --------------------- | ------------------------------------------------ | ------------- | ------: | --------- | --------------------------------------- |
| Four members          | `data.rpf!7!0`                                   | 4 (`zdd`)     |       4 | `0x5f70`  | `farlod_structures_01.#dr`              |
| Thirteen members      | `pack/core_restofworld/core_restofworld.rpf!6!0` | 4 (`zdd`)     |      13 | `0x7860`  | `ptfx_model_gore_bone_02.#dr`           |
| Eighty-three members  | `data.rpf!31!6`                                  | 4 (`zdd`)     |      83 | `0x314e0` | `ptfx_model_leaf_palm_01.#dr`           |
| One hundred and eight | `data.rpf!31!8`                                  | 4 (`zdd`)     |     108 | `0x3f810` | `ptfx_model_debris_glass_bottle_01.#dr` |

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

| Fragment          | Native chain     | Declared type | Member drawable                   | Split    | Component            | Scene                                                                                  |
| ----------------- | ---------------- | ------------- | --------------------------------- | -------- | -------------------- | -------------------------------------------------------------------------------------- |
| Tarot deck        | `levels.rpf!5!0` | 3 (`zft`)     | `prop_am_card_tarot_deck_01a.#ft` | `0x1980` | 1 mesh, 1 primitive  | 88 vertices, 76 triangles, 1 material, 3 textures, 4 bindings (3 resolved)             |
| Candlestick       | `levels.rpf!5!1` | 3 (`zft`)     | `prop_am_candlestick_02a.#ft`     | `0x3cc0` | 1 mesh, 2 primitives | 927 vertices, 1,232 triangles, 2 materials, 6 textures, 10 bindings (10 resolved)      |
| Weapon bolt       | `data.rpf!26!9`  | 3 (`zft`)     | `w_sg_goodwin_01_bolt_01_mid.#ft` | `0x1c30` | 1 mesh, 1 primitive  | 620 vertices, 372 triangles, 1 material, 3 textures, 4 bindings (3 resolved)           |
| Peacock taxidermy | `levels.rpf!5!8` | 3 (`zft`)     | `mint_peacock_taxidermy_01.#ft`   | `0xbbc0` | 1 mesh, 4 primitives | 41,613 vertices, 45,132 triangles, 4 materials, 16 textures, 19 bindings (16 resolved) |

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

| Resource          | Native chain     | Declared type | Member drawable                   | Bones | Roots | Depth |
| ----------------- | ---------------- | ------------- | --------------------------------- | ----: | ----: | ----: |
| Tarot deck        | `levels.rpf!5!0` | 3 (`zft`)     | `prop_am_card_tarot_deck_01a.#ft` |     3 |     1 |     3 |
| Weapon bolt       | `data.rpf!26!9`  | 3 (`zft`)     | `w_sg_goodwin_01_bolt_01_mid.#ft` |     3 |     1 |     3 |
| Candlestick       | `levels.rpf!5!1` | 3 (`zft`)     | `prop_am_candlestick_02a.#ft`     |     4 |     1 |     4 |
| Peacock taxidermy | `levels.rpf!5!8` | 3 (`zft`)     | `mint_peacock_taxidermy_01.#ft`   |    10 |     1 |    10 |
| Dominator model   | `levels.rpf!21!85` | 3 (`zft`)   | `dominator9_hi.#ft`               |   386 |     1 |    19 |
| Many roots        | `packs.rpf!26!0` | 3 (`zft`)     | `crm_rabbit_marsh_m_00.#ft`       |    98 |    10 |    15 |
| Largest in the census | `packs.rpf!26!255` | 3 (`zft`) | `ambient_femalebody.#ft`          |   596 |    16 |    24 |

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
`(I inferred single-bone)`. `Pose Mode` enters the session. The section then
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

### Peacock, weighted deformation

`levels.rpf!5!8`, declared type 3, `mint_peacock_taxidermy_01.#ft`. Ten bones,
one root, depth 10, four primitives, 41,613 vertices, all four deformable.

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

`levels.rpf!5!1`, declared type 3, `prop_am_candlestick_02a.#ft`. Four bones, one
root, two primitives, 927 vertices, both deformable, both single-influence, both
whole-primitive rigid.

| Step | Expected |
| ---- | -------- |
| Press `Pose Mode`, select `Candle` (index 3), press `Rotate Z+` twelve times | bone line reads `0 0 60` |
| Count the moved geometry | 139 of 927 vertices move, by at most 0.0182 m; the 139-vertex primitive is bound to `Candle` and turns as one piece |
| Check the other primitive | the 788-vertex primitive is bound to bone 2 and does not move at all |
| Press `Reset Bone` | both primitives return to the authored shape |

The earlier acceptance page called all 788 vertices affected. That was the
primitive's size, not the moved count; the measurement above replaces it.

### Dominator9, partial support on a 386-bone skeleton

`levels.rpf!21!85`, declared type 3, `dominator9_hi.#ft`. 386 bones, one root,
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

| Resource | Selector | Skeleton | Step | Expected |
| -------- | -------- | -------- | ---- | -------- |
| Ambient female body | `packs.rpf!26!255`, type 3, `ambient_femalebody.#ft` | 596 bones, 16 roots, depth 24 | `Pose Mode`, select `SKEL_ROOT` (index 0), `Rotate Z+` six times | `1 of 1 primitive(s) deform; 596 bone(s)`; 572 bones move and 24 do not, all 24 under the other 15 roots; the single 25-vertex primitive moves 9.15 m |
| Rabbit | `packs.rpf!26!0`, type 3, `crm_rabbit_marsh_m_00.#ft` | 98 bones, 10 roots, depth 15 | `Pose Mode`, select `SKEL_ROOT` (index 0), `Rotate Z+` six times | 81 bones move, the 17 bones under the other nine roots keep their transforms, and the 25-vertex primitive moves 9.17 m |

Both resources are fragments whose decoded LOD-0 member drawable holds one
25-vertex primitive bound to the root bone, so they verify pose propagation and
root independence rather than weighted character skinning. The 596-bone skeleton
uploads and renders, which is what the matrix buffer has to carry; the geometry
does not exercise it. The weighted large-skeleton case is the dominator above.

### Weighted data the decoder rejects

`packs.rpf!9!5` is a one-member drawable dictionary; member 0 is
`neckwearbowtie_mr1_000_regular_t_un_high_full.#dr` with 69 bones, 69 roots and
one 125-vertex primitive with four influences on 12 bones. Its four weights total
254 rather than 255 or 127, so the primitive is reported as unnormalised and is
not deformed.

| Step | Expected |
| ---- | -------- |
| Open `packs.rpf!9!5`, select member 0 | skeleton section reads `69 BONE(S) · 69 ROOT(S) · DEPTH 1`; no POSE section appears |
| Read the diagnostics | one line names the unnormalised blend weights and the total 254 |
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

`levels.rpf!5!252` (`prop_am_trophy_fish_06a_batchlod.#dr`, type 2) has no
skeleton and shows no POSE section. Its default render is unchanged: 171
vertices, 158 triangles, one mesh, one material, five reconstructed texture
bindings, complete geometry and textures.

The drawable dictionaries `data.rpf!7!0`, `data.rpf!31!6`, `data.rpf!31!8` and
`pack/core_restofworld/core_restofworld.rpf!6!0`, and the texture dictionary
`data.rpf!1!0` with five records, are unchanged checks from the earlier
acceptance runs.

## A dictionary member with a skeleton

`packs.rpf!9!5` is a drawable dictionary declared type 4 (`zdd`) with one member.
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

`levels.rpf!5!252` is declared type 2 (`zdr`) and opens in the **model viewer**
as a plain drawable: `prop_am_trophy_fish_06a_batchlod.#dr`, resource
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

`data.rpf!1!0` is declared type 5 (`ztd`) and opens in the **texture dictionary
viewer**: 5 hashes of capacity 5, 5 records, allocation partition agrees.

## Correction to the previous handoff

The earlier selector list gave `levels.rpf!5!0` for the four-member dictionary.
That row is the tarot-deck fragment (`prop_am_card_tarot_deck_01a.#ft`). The
four-member dictionary is `data.rpf!7!0`, as listed above. Every other selector
in this page was re-resolved from the installation census and re-read in place.

The skeleton list once called `packs.rpf!26!255` a dictionary member. That row
is declared type 3 (`zft`), a fragment; the 596-bone member drawable is
`ambient_femalebody.#ft`, not a dictionary member. `packs.rpf!9!5` is the
dictionary, and it has one member rather than a member list to switch through.
