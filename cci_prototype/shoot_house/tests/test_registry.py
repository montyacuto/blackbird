from __future__ import annotations

from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cci_prototype.shoot_house.registry import create_house, plugin_for_record


EXPECTED = {
    "cline": ("cci_prototype.cline_house.house", "ClineHousePlugin"),
    "sandbox-escape": ("cci_prototype.sandbox_escape_house.house", "SandboxEscapePlugin"),
    "midnight-blizzard": (
        "cci_prototype.midnight_blizzard_house.house", "MidnightBlizzardPlugin"),
    "hackerbot-claw": ("cci_prototype.hackerbot_claw_house.house", "HackerbotClawPlugin"),
    "trivy-litellm": ("cci_prototype.trivy_litellm_house.house", "TrivyLiteLLMPlugin"),
}


class RegistryTests(unittest.TestCase):
    def test_only_neutral_ids_are_registered_and_records_reconstruct_plugins(self):
        loaded = []
        plugin_types = {}
        for house_id, (_, class_name) in EXPECTED.items():
            def from_record(cls, record):
                return cls(**record.get("configuration", {}))
            plugin_types[class_name] = type(class_name, (), {
                "house_id": house_id,
                "from_record": classmethod(from_record),
                "__init__": lambda self, **configuration: setattr(
                    self, "configuration", configuration),
            })

        def import_module(name):
            loaded.append(name)
            matches = [item for item in EXPECTED.values() if item[0] == name]
            return SimpleNamespace(**{item[1]: plugin_types[item[1]] for item in matches})

        with patch("importlib.import_module", side_effect=import_module):
            for house_id, (module_name, class_name) in EXPECTED.items():
                with self.subTest(house=house_id):
                    plugin = create_house(house_id, synthetic_option=house_id)
                    self.assertIsInstance(plugin, plugin_types[class_name])
                    self.assertEqual(plugin.house_id, house_id)
                    self.assertEqual(plugin.configuration, {"synthetic_option": house_id})
                    reconstructed = plugin_for_record({
                        "house_id": house_id, "configuration": {"saved": True},
                    })
                    self.assertEqual(reconstructed.configuration, {"saved": True})
                    self.assertIn(module_name, loaded)

        for old_id in ("sandbox", "cline-development", "midnight-blizzard-development"):
            with self.subTest(rejected=old_id), self.assertRaises(ValueError):
                create_house(old_id)

    def test_unknown_or_missing_record_identity_is_rejected(self):
        with self.assertRaises(ValueError):
            create_house("unknown-house")
        with self.assertRaises(ValueError):
            plugin_for_record({"house_id": "unknown-house"})
        with self.assertRaises(ValueError):
            plugin_for_record({})


if __name__ == "__main__":
    unittest.main()
