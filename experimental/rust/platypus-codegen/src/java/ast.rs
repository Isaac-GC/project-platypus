/// AST node types — translates codegen/java/ast.py

/// Sequence of basic blocks forming a straight-line region.
#[derive(Debug, Clone)]
pub struct SequenceNode {
    /// A single block id (None if this node holds multiple blocks).
    pub block: Option<usize>,
    /// Multiple block ids when the sequence spans more than one block.
    pub blocks: Vec<usize>,
}

impl SequenceNode {
    pub fn single(block_id: usize) -> Self {
        SequenceNode { block: Some(block_id), blocks: Vec::new() }
    }

    pub fn multi(blocks: Vec<usize>) -> Self {
        SequenceNode { block: None, blocks }
    }
}

/// Boxed AST node — used wherever Python used `object`.
#[derive(Debug, Clone)]
pub enum AstNode {
    Sequence(SequenceNode),
    /// A flat ordered list of AST nodes — what Python's `[a, b, c]`
    /// would express directly. Added to fix `prepend_ast`, which
    /// previously wrapped the continuation of an if/while in an
    /// `AstNode::Loop` (rendered as `while(true)` by the generator)
    /// because there was nowhere else to attach a tail. With this
    /// variant the tail is simply the second element of a `Compound`.
    Compound(Vec<AstNode>),
    If(Box<IfNode>),
    While(Box<WhileNode>),
    DoWhile(Box<DoWhileNode>),
    Loop(Box<LoopNode>),
}

/// if / if-else structure.
#[derive(Debug, Clone)]
pub struct IfNode {
    pub condition:  String,
    pub true_body:  Box<AstNode>,
    pub false_body: Option<Box<AstNode>>,
    /// Block id of the if-header block.
    pub header:     usize,
}

/// while loop.
#[derive(Debug, Clone)]
pub struct WhileNode {
    pub condition: String,
    pub body:      Box<AstNode>,
    pub header:    usize,
}

/// do-while loop.
#[derive(Debug, Clone)]
pub struct DoWhileNode {
    pub condition: String,
    pub body:      Box<AstNode>,
}

/// Infinite / unrecognised loop.
#[derive(Debug, Clone)]
pub struct LoopNode {
    pub body:   Box<AstNode>,
    pub header: usize,
}
