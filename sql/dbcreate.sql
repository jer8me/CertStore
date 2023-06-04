-- This will destroy an existing 'test' instance
DROP DATABASE IF EXISTS `test`;
CREATE DATABASE IF NOT EXISTS `test`;
USE `test`;

-- TEST table
DROP TABLE IF EXISTS `TEST`;
CREATE TABLE IF NOT EXISTS `TEST` (
  `id` INT NOT NULL,
  `name` VARCHAR(100) NOT NULL,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Insert some test data
INSERT INTO `TEST` (`id`,`name`) VALUES (1, 'Jerome');
