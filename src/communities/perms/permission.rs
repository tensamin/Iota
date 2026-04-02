use json::JsonValue;
use uuid::Uuid;

pub struct Permission {
    pub id: Uuid,
    pub name: String,
}
impl Permission {
    pub fn new(id: Uuid, name: String) -> Self {
        Permission { id, name }
    }
    pub fn to_json(&self) -> JsonValue {
        json::object! {
            "id" => self.id.to_string(),
            "name" => self.name.clone()
        }
    }
    pub fn from_json(json: JsonValue) -> Self {
        Permission {
            id: Uuid::parse_str(json["id"].as_str().unwrap()).unwrap(),
            name: json["name"].as_str().unwrap().to_string(),
        }
    }
    pub fn to_string(&self) -> String {
        self.to_json().as_str().unwrap().to_string()
    }
}
