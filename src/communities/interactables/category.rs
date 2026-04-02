use crate::communities::{community::Community, interactables::interactable::Interactable};
use async_trait::async_trait;
use json::JsonValue;
use std::any::Any;
use std::sync::Arc;
use ttp_core::CommunicationValue;
use uuid::Uuid;

pub struct Category {
    id: Uuid,
    name: String,
    path: String,
    community: Arc<Community>,
    children: Vec<Arc<Box<dyn Interactable>>>,
}
impl Category {
    pub fn new() -> Category {
        Category {
            id: Uuid::new_v4(),
            name: String::new(),
            path: String::new(),
            community: Arc::new(Community::new()),
            children: Vec::new(),
        }
    }
    pub fn get_child(&self, path: String, name: String) -> Option<Arc<Box<dyn Interactable>>> {
        if path.is_empty() {
            self.children
                .iter()
                .find(|child| child.get_name() == &name)
                .cloned()
        } else {
            let sub_module = path.split("/").next().unwrap();
            let next = self
                .children
                .iter()
                .find(|child| child.get_name() == sub_module)
                .unwrap();
            if next.get_codec() == "category" {
                let next_cat = next.as_any().downcast_ref::<Category>().unwrap();
                next_cat.get_child(path, name)
            } else {
                Some(next.clone())
            }
        }
    }
    pub fn get_children(&self) -> Vec<Arc<Box<dyn Interactable>>> {
        self.children.iter().map(|child| child.clone()).collect()
    }
}

#[async_trait]
impl Interactable for Category {
    fn get_id(&self) -> &Uuid {
        &self.id
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    fn get_codec(&self) -> String {
        "category".to_string()
    }
    fn set_name(&mut self, name: String) {
        self.name = name;
    }
    fn set_path(&mut self, path: String) {
        self.path = path;
    }
    fn get_community(&self) -> &Arc<Community> {
        &self.community
    }
    fn set_community(&mut self, community: Arc<Community>) {
        self.community = community;
    }
    fn get_name(&self) -> &String {
        &self.name
    }
    fn get_path(&self) -> &String {
        &self.path
    }
    fn get_total_path(&self) -> String {
        String::new() + &self.path + "/" + &self.name
    }
    fn get_data(&self) -> JsonValue {
        let mut v = JsonValue::new_object();
        for child in &self.children {
            let mut subject = JsonValue::new_object();
            subject["codec"] = JsonValue::String(child.get_codec());
            subject["data"] = child.get_data();
            v[child.get_name()] = subject;
        }
        v
    }
    async fn run_function(&self, _cv: CommunicationValue) -> CommunicationValue {
        CommunicationValue::new(CommunicationType::error)
    }
    fn to_json(&self) -> JsonValue {
        let mut v = JsonValue::new_object();
        v["children"] = JsonValue::new_array();
        for child in &self.children {
            let _ = v["children"].push(child.to_json());
        }
        v
    }
    fn load(
        &mut self,
        community: Arc<Community>,
        id: Uuid,
        path: String,
        name: String,
        _json: &JsonValue,
    ) {
        self.community = community;
        self.id = id;
        self.name = name;
        self.path = path;
    }
}
