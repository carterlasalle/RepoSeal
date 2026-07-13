import unittest

from reposeal import RepoSeal, RepoSealError


class RepoSealClientTests(unittest.TestCase):
    def test_configuration_is_explicit(self) -> None:
        client = RepoSeal("/tmp/reposeal", policy="policy.yaml", lockfile="custom.lock")
        self.assertEqual(client.binary, "/tmp/reposeal")
        self.assertEqual(client.policy, "policy.yaml")
        self.assertEqual(client.lockfile, "custom.lock")

    def test_missing_binary_is_operational_error(self) -> None:
        client = RepoSeal("/definitely/missing/reposeal")
        with self.assertRaises(FileNotFoundError):
            client.verify("github:astral-sh/uv", offline=True)


if __name__ == "__main__":
    unittest.main()

