# 3D models (GLTF / GLB)

Drop Draco-compressed `.glb` files here, then render one with the R3F stage:

```tsx
import { ModelStage } from '../components/three/ModelStage'

<ModelStage src="/models/burning-bush.glb" className="h-[340px] w-full" />
```

`ModelStage` loads via drei's `useGLTF(src, true)` — the `true` enables the
Draco decoder, so compressed files just work. With no `src` it renders a
procedural ember orb (no asset required).

## Authoring → web pipeline

1. **Model** in Blender or Spline.
2. **Export GLB**
   - Blender: File → Export → glTF 2.0 (.glb), enable *Compression* (Draco).
   - Spline: Export → GLTF/GLB (or Export → React for a live `.splinecode`
     scene, used with `components/three/SplineEmbed.tsx`).
3. **Compress** further if needed:
   ```bash
   npx gltf-pipeline -i model.glb -o burning-bush.glb -d   # -d = Draco
   ```
4. Save the result in this folder and point `ModelStage` at `/models/<file>.glb`.

Keep models small (target < 2 MB). Prefer GLB over GLTF+bin for a single file.
