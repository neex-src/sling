if (/\s/.test(String(object.userName))) { throw { code: 403, message: "Policy validation failed: userName has spaces" }; }
