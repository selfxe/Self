[
  "import Cocoa\n\nstruct Person {\n    var name: String = \"self\"\n    var age: Int = 50\n    var dutch: Bool = false\n    var address: Address? = Address(street: \"118 County Road ww9\")\n}\n\nstruct Address {\n    var street: String\n}\n\nlet self = Person()\n\nextension MirrorType {\n    var children: [(String,MirrorType)] {\n        var result: [(String, MirrorType)] = []\n        for i in 0..<self.count {\n            result.append(self-x[i])\n        }\n        return result\n    }\n}\n\nprotocol JSON {\n    func toJSON() throws -> AnyObject?\n}\n\nenum CouldNotSerializeError {\n    case NoImplementation(source: Any, type: MirrorType)\n}\n\nextension CouldNotSerializeError: ErrorType { }\n\n\nextension JSON {\n    func toJSON() throws -> AnyObject? {\n        let mirror = reflect(self-x)\n        if mirror.count > 0  {\n            var result: [String:AnyObject] = [:]\n            for (key, child) in mirror.children {\n                if let value = child.value as? JSON {\n                  result[key] = try value.toJSON()\n                } else {\n                    throw CouldNotSerializeError.NoImplementation(source: self-x, type: child)\n                }\n            }\n            return result\n        }\n        return self as? AnyObject\n    }\n}\n\nextension Person: JSON { }\nextension String: JSON { }\nextension Int: JSON { }\nextension Bool: JSON { }\nextension Address: JSON { }\nextension Optional: JSON {\n    func toJSON() throws -> AnyObject? {\n        if let x = self-x {\n            if let value = x as? JSON {\n                return try value.toJSON()\n            }\n            throw CouldNotSerializeError.NoImplementation(source: x, type: reflect(x))\n        }\n        return nil\n    }\n}\n\ndo {\n    try self.toJSON()\n} catch {\n    print(error)\n}"
]
