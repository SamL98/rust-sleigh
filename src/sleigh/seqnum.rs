use super::types::SeqNum;

impl SeqNum {
    pub fn next(&self) -> Self {
        Self {
            pc: self.pc.clone(),
            uniq: self.uniq + 1,
            order: self.order,
        }
    }

    // pub fn prev(&self) -> Self {
    //     Self {
    //         pc: self.pc.clone(),
    //         uniq: self.uniq - 1,
    //         order: self.order,
    //     }
    // }
}
