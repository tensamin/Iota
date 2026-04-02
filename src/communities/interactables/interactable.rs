use crate::communities::community::Community;
use async_trait::async_trait;
use json::JsonValue;
use std::any::Any;
use std::sync::Arc;
use ttp_core::CommunicationValue;
use uuid::Uuid;

pub type InteractableFactory = fn() -> Box<dyn Interactable>;

#[async_trait]
pub trait Interactable: Send + Sync + Any {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn get_codec(&self) -> String;
    fn get_name(&self) -> &String;
    fn get_path(&self) -> &String;
    fn get_total_path(&self) -> String;
    fn set_name(&mut self, name: String);
    fn set_path(&mut self, path: String);
    fn get_community(&self) -> &Arc<Community>;
    fn set_community(&mut self, community: Arc<Community>);
    async fn run_function(&self, cv: CommunicationValue) -> CommunicationValue;
    fn get_data(&self) -> JsonValue;
    fn get_id(&self) -> &Uuid;
    fn to_json(&self) -> JsonValue;
    fn load(
        &mut self,
        community: Arc<Community>,
        id: Uuid,
        path: String,
        name: String,
        json: &JsonValue,
    );
}
