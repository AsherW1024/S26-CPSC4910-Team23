import importlib
import unittest
from unittest.mock import MagicMock, patch


def load_application_module():
    fake_cursor = MagicMock()
    fake_cursor.__enter__.return_value = fake_cursor
    fake_cursor.__exit__.return_value = False
    fake_connection = MagicMock()
    fake_connection.cursor.return_value = fake_cursor
    with patch('pymysql.connect', return_value=fake_connection):
        import application
        return importlib.reload(application)


application = load_application_module()


class Sprint9CheckoutGuardrailTests(unittest.TestCase):
    def setUp(self):
        application.application.config['TESTING'] = True
        self.client = application.application.test_client()

    @patch('application.getCartData')
    @patch('application.get_driver_org_membership')
    def test_validate_redemption_request_blocks_missing_sponsor_affiliation(self, mock_membership, mock_cart):
        mock_membership.return_value = None
        mock_cart.return_value = []

        result = application.validate_redemption_request(5, 3)

        self.assertFalse(result["ok"])
        self.assertIn("sponsor affiliation", result["message"].lower())

    @patch('application.adjustDriverPoints')
    @patch('application.updateDb')
    @patch('application.getDbConnection')
    @patch('application.log_redemption_denial')
    @patch('application.validate_redemption_request')
    def test_make_order_blocks_when_total_changes_after_confirm(
        self,
        mock_validate,
        mock_log_denial,
        mock_connection,
        mock_update,
        mock_adjust
    ):
        mock_validate.return_value = {
            "ok": True,
            "message": "",
            "cart": [
                {"id": 1, "price": 30, "quantity": 1, "title": "Headphones"}
            ],
            "total": 30,
            "driver_points": 100
        }

        with self.client.session_transaction() as sess:
            sess["UserID"] = 5
            sess["OrgID"] = 3
            sess["role"] = "Driver"

        response = self.client.post(
            "/orders",
            data={
                "address": "123 Main St",
                "city": "Clemson",
                "state": "SC",
                "expected_total": "20"
            },
            follow_redirects=False
        )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(mock_log_denial.called)
        self.assertFalse(mock_adjust.called)

    def test_support_route_redirects_to_bug_report(self):
        response = self.client.get("/support", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/bugReport", response.location)


if __name__ == '__main__':
    unittest.main()