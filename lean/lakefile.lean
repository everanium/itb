import Lake
open Lake DSL

package «itb» where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib «ITB» where
  roots := #[`ITB]
