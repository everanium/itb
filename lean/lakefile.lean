import Lake
open Lake DSL

package «itb» where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib «ITB» where
  roots := #[`ITB]

@[default_target]
lean_lib «Posit» where
  roots := #[`ITB.Posit]

@[default_target]
lean_lib «PipelineSpec» where
  roots := #[`ITB.PipelineSpec128, `ITB.PipelineSpec256, `ITB.PipelineSpec512]

@[default_target]
lean_lib «Apps» where
  roots := #[`Apps.ThreeToEight]
