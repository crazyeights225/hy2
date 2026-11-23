


## model.py:

Methods left out of the state class (MState). Nothing in hy2 calls any of these. Each reads data hy2's model builder doesn't produce:
  - lookupByVarLabelDep and lookupByVarLabel need per-instance dvec.
  - lookup_dependency needs MVar.exportDep.
  - load_conditions needs deep_deps.
  - export_condition needs dvec and deps.
  - check_linked_vars needs v.ls/v.rs.
  - check_dynamic and check_dynamic_vars need v.op and v.ls, and set is_dynamic.
  - __repr__ prints the old variable fields (lid, size_estimate, casts, telescope, …).


