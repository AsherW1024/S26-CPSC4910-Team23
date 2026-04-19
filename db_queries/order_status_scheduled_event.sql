/* 
This event runs once every day. 
It checks if todays date equals or is past the order estimated arrival date.
(Only if the order status is not "Delivered")
If the estimated order date has arrived, the order status is changed to delivered.
This was created to mock having real-time order mailing status data.
*/

CREATE DEFINER=`CPSC4911_admin`@`%` EVENT `update_order_status` ON SCHEDULE EVERY 1 DAY STARTS '2026-04-14 18:36:52' ON COMPLETION NOT PRESERVE ENABLE DO UPDATE Orders
	SET orderStatus = "Delivered"
	WHERE NOW() >= estimatedArrival
		AND orderStatus <> "Delivered"