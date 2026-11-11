package db

// The asset lifecycle is a small state machine. Every change of State goes through
// Repos.TransitionAsset (or a query that moves along one of these edges), which checks the edge
// here and then compare-and-sets the row, so two writers can never both win a transition.
//
//	created -> uploading -> committed -> processing -> ready
//	   |           |            |            |
//	   +-----------+------------+------------+-> failed
//	every state except deleted -> deleted     (deletion arrives with a later task)
//
// "processing -> committed" and every other backward edge are not allowed: a retried job
// re-enters processing from processing, which is not a state change.
var assetEdges = map[AssetState][]AssetState{
	AssetCreated:    {AssetUploading, AssetFailed, AssetDeleted},
	AssetUploading:  {AssetCommitted, AssetFailed, AssetDeleted},
	AssetCommitted:  {AssetProcessing, AssetFailed, AssetDeleted},
	AssetProcessing: {AssetReady, AssetFailed, AssetDeleted},
	AssetReady:      {AssetDeleted},
	AssetFailed:     {AssetDeleted},
	AssetDeleted:    nil,
}

// AssetStates returns every state, in lifecycle order.
func AssetStates() []AssetState {
	return []AssetState{
		AssetCreated, AssetUploading, AssetCommitted, AssetProcessing, AssetReady, AssetFailed, AssetDeleted,
	}
}

// CanTransitionTo reports whether the lifecycle allows moving from s to to. A state never
// transitions to itself.
func (s AssetState) CanTransitionTo(to AssetState) bool {
	for _, next := range assetEdges[s] {
		if next == to {
			return true
		}
	}
	return false
}

// Terminal reports whether no transition leaves s.
func (s AssetState) Terminal() bool { return len(assetEdges[s]) == 0 }

// Accepting reports whether an upload may still send bytes for an asset in state s.
func (s AssetState) Accepting() bool { return s == AssetCreated || s == AssetUploading }
