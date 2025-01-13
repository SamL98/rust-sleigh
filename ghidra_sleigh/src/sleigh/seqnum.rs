use super::types::SeqNum;

pub trait SeqNumIface {
    fn next(&self) -> Self;
    fn prev(&self) -> Self;
}

impl SeqNumIface for SeqNum {
    fn next(&self) -> Self {
        SeqNum {
            pc: self.pc.clone(),
            uniq: self.uniq + 1,
            order: self.order,
        }
    }

    fn prev(&self) -> Self {
        SeqNum {
            pc: self.pc.clone(),
            uniq: self.uniq - 1,
            order: self.order,
        }
    }
}
