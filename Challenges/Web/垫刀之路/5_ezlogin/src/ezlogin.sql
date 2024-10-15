/*
 Navicat Premium Dump SQL

 Source Server         : asdf
 Source Server Type    : MariaDB
 Source Server Version : 101108 (10.11.8-MariaDB)
 Source Host           : localhost:3306
 Source Schema         : ezlogin

 Target Server Type    : MariaDB
 Target Server Version : 101108 (10.11.8-MariaDB)
 File Encoding         : 65001

 Date: 18/08/2024 16:20:19
*/
alter user 'root'@'localhost' identified by 'root';
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

create database ezlogin;
use ezlogin;

-- ----------------------------
-- Table structure for user
-- ----------------------------
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) DEFAULT NULL,
  `password` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

-- ----------------------------
-- Records of user
-- ----------------------------
BEGIN;
INSERT INTO `user` (`id`, `username`, `password`) VALUES (1, 'admin123', 'teMp_p3s5w0Ord');
COMMIT;

SET FOREIGN_KEY_CHECKS = 1;

