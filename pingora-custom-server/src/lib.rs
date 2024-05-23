#![feature(btree_cursors)]
#![feature(let_chains)]
extern crate pingora;

mod app;
mod client;
pub mod proxy;
pub(crate) mod server;
mod service;

mod discovery;
