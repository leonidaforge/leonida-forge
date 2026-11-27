# Manual acceptance: drawable dictionaries and fragments

This page lists the exact archives, rows and expected results to check the two
model features by hand. It is written for the maintainer, so every selector is
the original native path in the release installation, not a copy.

## Build and launch

| Item               | Value                                                                                                         |
| ------------------ | ------------------------------------------------------------------------------------------------------------- |
| Release executable | `E:\source\leonidaforge\worktrees\fragment-dictionary-support\leonida-forge\target\release\leonida-forge.exe` |
| Game root          | `D:\GTA VI` (read only)                                                                                       |
| Texture stores     | `D:\GTA VI\data\ttdb`                                                                                         |

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
