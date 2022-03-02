# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased] - yyyy-mm-dd
### Added
### Changed
### Fixed

## [1.5.0] - 2022-03-02
### Added
- add php 7.2 dependency
### Changed
- removed property type declarations

## [1.4.3] - 2022-02-15
### Changed
- added $region arg to constructor so aws region can be changed

## [1.4.2] - 2021-10-07
### Changed
- set default value for access() $key

## [1.4.0] - 2021-10-07
### Added
- additional getter methods

### Changed
- access() method key is optional in order to return full json from secret
- updated method visibility on several methods
- move some procedural code to separate methods
- composer update

## [1.3.3] - 2021-09-28
### Changed
- remove request to instance id url 

## [1.3.2] - 2021-09-27
### Changed
- check openssl cipher algo by case

## [1.3.1] - 2021-09-23
### Changed
- update ip retrieval for $instance_id

## [1.3.0] - 2021-09-16
### Changed
- removed use of credentials in SDK services in favor of credential provider chain
- composer updates

## [1.2.3] - 2021-09-03
### Changed
- update log name for more efficient filtering

## [1.2.2] - 2021-09-02
### Changed
- access() and fetchFromSource() return null on thrown exceptions

## [1.2.1] - 2021-08-25
### Changed
- readme

## [1.2.0] - 2021-08-25
### Added
- Included Changelog

### Changed
- Removed notify() method in favor of CloudWatch alarm to SNS