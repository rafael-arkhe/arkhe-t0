pub struct OpenClawBftConsensus {
    pub quorum_size: usize,
}

impl OpenClawBftConsensus {
    pub fn new(total_nodes: usize) -> Self {
        let quorum_size = (total_nodes * 2) / 3 + 1;
        Self { quorum_size }
    }

    pub fn can_finalize(&self, votes: usize) -> bool {
        votes >= self.quorum_size
    }
}
