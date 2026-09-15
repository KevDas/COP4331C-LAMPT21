-- ============================================================
-- SQL Full Reset Script: resetdb.sql
-- Project: COP4331 Contact Manager
-- Description: Drops existing tables if present, recreates schema,
--              seeds users and contacts, and sets up user permissions.
--
-- Seed logins (passwords are stored as bcrypt hashes):
--   Admin  / COP4331  (IsAdmin=1)
--   Admin2 / COP4331  (IsAdmin=1)
--   SamH   / Test     (IsAdmin=0)
-- ============================================================

CREATE DATABASE IF NOT EXISTS `ContactsAppDB`
    DEFAULT CHARACTER SET utf8mb4
    DEFAULT COLLATE utf8mb4_unicode_ci;

USE `ContactsAppDB`;

DROP TABLE IF EXISTS `Contacts`;
DROP TABLE IF EXISTS `Users`;

CREATE TABLE `Users` (
    `ID` INT NOT NULL AUTO_INCREMENT,
    `FirstName` VARCHAR(50) NOT NULL DEFAULT '',
    `LastName` VARCHAR(50) NOT NULL DEFAULT '',
    `Login` VARCHAR(50) NOT NULL DEFAULT '',
    `Password` VARCHAR(255) NOT NULL DEFAULT '',
    `IsAdmin` TINYINT(1) NOT NULL DEFAULT 0,
    `Disabled` TINYINT(1) NOT NULL DEFAULT 0,
    PRIMARY KEY (`ID`),
    UNIQUE KEY `idx_users_login` (`Login`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `Contacts` (
    `ID` INT NOT NULL AUTO_INCREMENT,
    `UserID` INT NOT NULL DEFAULT 0,
    `FirstName` VARCHAR(50) NOT NULL DEFAULT '',
    `LastName` VARCHAR(50) NOT NULL DEFAULT '',
    `Email` VARCHAR(100) NOT NULL DEFAULT '',
    `Phone` VARCHAR(50) NOT NULL DEFAULT '',
    PRIMARY KEY (`ID`),
    INDEX `idx_contacts_userid` (`UserID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO `Users` (`FirstName`, `LastName`, `Login`, `Password`, `IsAdmin`, `Disabled`) VALUES
('Rick', 'Admin', 'Admin', '$2y$05$oELRSYZ6e.hlWSqHXrdSWudSTQPc99XqiWlt8bNxzV1V3Q.BQn3Ze', 1, 0),
('Pat', 'Admin', 'Admin2', '$2y$05$oELRSYZ6e.hlWSqHXrdSWudSTQPc99XqiWlt8bNxzV1V3Q.BQn3Ze', 1, 0),
('Sam', 'Hill', 'SamH', '$2y$05$icfKrGdmnzylkruq0sur3.E.4u1oG3xvcV.QuNyIWsoCkoxvGUQXy', 0, 0);

-- Contacts for Admin (UserID 1)
INSERT INTO `Contacts` (`UserID`, `FirstName`, `LastName`, `Email`, `Phone`) VALUES
(1, 'Ada', 'Lovelace', 'ada@example.com', '407-555-0100'),
(1, 'Alan', 'Turing', 'alan@example.com', '407-555-0101');

-- Contacts for SamH (UserID 3)
INSERT INTO `Contacts` (`UserID`, `FirstName`, `LastName`, `Email`, `Phone`) VALUES
(3, 'Grace', 'Hopper', 'grace@example.com', '407-555-0200'),
(3, 'Katherine', 'Johnson', 'katherine@example.com', '407-555-0201'),
(3, 'Dorothy', 'Vaughan', 'dorothy@example.com', '407-555-0202');

CREATE USER IF NOT EXISTS 'ContactsAppUser'@'localhost' IDENTIFIED BY 'WeLoveCOP4331!';
GRANT ALL PRIVILEGES ON `ContactsAppDB`.* TO 'ContactsAppUser'@'localhost';

CREATE USER IF NOT EXISTS 'ContactsAppUser'@'%' IDENTIFIED BY 'WeLoveCOP4331!';
GRANT ALL PRIVILEGES ON `ContactsAppDB`.* TO 'ContactsAppUser'@'%';

FLUSH PRIVILEGES;
