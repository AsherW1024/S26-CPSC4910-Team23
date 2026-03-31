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


class Sprint8FeatureTests(unittest.TestCase):
    def setUp(self):
        application.application.config['TESTING'] = True
        self.client = application.application.test_client()

    def test_validate_bulk_upload_line_rejects_admin_record_type(self):
        with self.assertRaises(ValueError):
            application.validate_bulk_upload_line(['A', 'Org', 'First', 'Last', 'admin@example.com'])

    @patch('application.create_point_adjustment_for_driver')
    @patch('application.make_bulk_username', return_value='newdriver')
    @patch('application.generate_password_hash', return_value='hashed')
    @patch('application.updateDb')
    @patch('application.paramQueryDb')
    def test_process_admin_bulk_lines_continues_after_error(self, mock_param, mock_update, mock_hash, mock_username, mock_adjust):
        def fake_param(query, params=None):
            if 'FROM Organizations WHERE Name=%s' in query:
                if params == ('Acme',):
                    return {'OrganizationID': 7}
                return None
            if 'FROM Users WHERE Email=%s' in query:
                if params == ('driver@example.com',):
                    return None
                if params == ('admin@example.com',):
                    return {'UserID': 2, 'Username': 'root', 'UserType': 'Admin'}
            return None

        mock_param.side_effect = fake_param
        lines = [
            'O|Acme',
            'D|Acme|Taylor|Driver|driver@example.com|25|Safe driving',
            'D|Missing Org|Bad|Driver|bad@example.com|5|Test',
            'S|Acme|Admin|User|admin@example.com',
        ]

        result = application.process_admin_bulk_lines(lines)
        self.assertEqual(result['success_count'], 2)
        self.assertEqual(result['error_count'], 2)
        messages = [entry['message'] for entry in result['results']]
        self.assertTrue(any('Organization ready: Acme' in msg or 'Organization created: Acme' in msg for msg in messages))
        self.assertTrue(any('Driver created: driver@example.com' in msg for msg in messages))
        self.assertTrue(any('Organization does not exist: Missing Org' in msg for msg in messages))
        self.assertTrue(any('Admin users cannot be created or modified through bulk upload.' in msg for msg in messages))

    def test_driver_points_csv_export_route_uses_summary_rows(self):
        fake_summary = {
            'balance': 99,
            'pending': [],
            'transactions': [
                {
                    'display_date': 'Mar 30, 2026',
                    'display_time': '10:00 AM',
                    'transaction_type': 'Award',
                    'delta_points': 10,
                    'balance_after': 99,
                    'description': 'Weekly safe-driving bonus',
                }
            ]
        }
        with self.client.session_transaction() as sess:
            sess['UserID'] = 5
            sess['role'] = 'Driver'
            sess['OrgID'] = 3
        with patch('application.get_driver_point_history', return_value=fake_summary):
            response = self.client.get('/driver/points?format=csv')
        self.assertEqual(response.status_code, 200)
        body = response.data.decode('utf-8')
        self.assertIn('TransactionType,PointsChange,BalanceAfter,Description', body)
        self.assertIn('Award,10,99,Weekly safe-driving bonus', body)


if __name__ == '__main__':
    unittest.main()