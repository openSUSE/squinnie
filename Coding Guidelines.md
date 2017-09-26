# Coding guidelines

This project does mostly follow the guidelines as they are proposed in several PEPs (especially PEP8). However, due to personal preferences of the original creator, there are a few exceptions which are listed here.

## member variables

Member variables of class SHOULD be prefix with `m_`. Example: `self.m_mydata = 123`. This is to easily identify class members amongst funtions, static variables and the like.

## class method names

Class methods MUST be named in lowerCamelCase. Example: `def processUsageData(self, input)`. Private functions (that are functions which are not meant to be called from outside of the class or its descendants) SHOULD be prefix with an underscore. Example: `def _myPrivateFn(self)`.

## File names

Files names (except for meta files like this one) should not contain spaces. Ideally the should only contain alphanumeric characters and `-_.`.
