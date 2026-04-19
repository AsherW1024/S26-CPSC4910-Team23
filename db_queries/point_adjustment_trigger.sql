/*
This trigger was created to automate updating a driver's total point value.
With how we chose to set up our db, one table is used to log changes to a driver's points
and another table actually holds the driver's point total.
This meant we had to update multiple tables for simply updating a driver's points.
To make things simpler, this trigger will automatically update a driver's point total when a point adjustment row is added.
*/

CREATE DEFINER=`CPSC4911_admin`@`%` TRIGGER `PointAdjustments_AFTER_INSERT` AFTER INSERT ON `PointAdjustments` FOR EACH ROW BEGIN
	DECLARE uID INT;

	SELECT UserID
    INTO uID
    FROM Users
    WHERE Username=NEW.DriverUName
    LIMIT 1;

	UPDATE DriverOrganizations
	SET TotalPoints=NEW.DriverTotalPoints
	WHERE
		DriverID=uID
		AND OrganizationID=NEW.OrganizationID;
END