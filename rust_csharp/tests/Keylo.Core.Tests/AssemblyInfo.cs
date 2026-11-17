// The tests share the real Credential Manager. Running classes in parallel let a cleanup listing
// race another class's writes and leave entries behind, so they run one at a time.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
