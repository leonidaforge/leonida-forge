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
`reference pose` or `edited pose`. `Pose Mode` enters the session; the section
then offers `authored` and `posed`, `Influence View`, one row of six rotation
buttons, one row of six translation buttons, `Reset Bone` and `Reset Pose`.

Rotations are Euler XYZ in degrees, five degrees per press, in the bone's parent
space. Translations are metres in the same space, five centimetres per press.
Nothing is written to the resource, no pose is saved, and closing the window
discards it.

1. Open `levels.rpf!5!8` and press `Pose Mode`. The header reads
   `4 of 4 primitive(s) deform; 10 bone(s)` and `reference pose`, and the mesh is
   unchanged.
2. Select `Tail_01` and press `Rotate Z+` eight times. The bone line reads
   `40 deg`, the label reads `edited pose`, and the tail fans out while the
   pedestal, the legs and the floor stay.
3. Press `Influence View`. The tail turns orange and yellow by weight, geometry
   with no weight stays neutral grey, and the display switches to `posed`.
4. Press `authored`. The authored mesh returns while the skeleton overlay stays
   at the edited pose; `posed` restores the deformation.
5. Press `Reset Bone`. The tail returns to the reference pose and the label reads
   `reference pose` again.
6. Press `Reset View`. The camera frames the deformed geometry, not the authored
   one.
7. Press `Exit Pose`. The authored mesh and the reference skeleton return, and
   the POSE section keeps only its header.
8. Open `levels.rpf!5!1`, press `Pose Mode`, select `Candle` and press
   `Rotate Z+` twelve times. The candle holder turns 60 degrees about the bone
   rigidly and the base stays.
9. Open `levels.rpf!21!85`. The header reads
   `29 of 37 primitive(s) deform; 386 bone(s)`; the eight geometries without a
   weight attribute stay authored.

The same numbers are what the harness reports for those two chains: the peacock
moves 24,496 of the 25,456 vertices of its widest-influence primitive with a
largest displacement of 1.19 m, and the candlestick moves all 788 vertices of the
primitive it shares with `Candle` with a largest displacement of 0.018 m. A GPU
compute probe over the same matrices agrees with the CPU reference on every one
of those vertices, worst difference `3.6e-7` m and `3.7e-9` m.

A resource without a verified influence set shows no POSE section at all: for
example the four-member dictionary `data.rpf!7!0`, whose members carry no
skeleton.

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
