# Coding guidelines

This project does mostly follow the guidelines as they are proposed in several
PEPs (especially PEP8). However, there are a few exceptions which are listed
here.

## Member Variables

Member variables of class SHOULD be prefix with `m_`. Example: `self.m_mydata
= 123`. This is to easily identify class members amongst funtions, static
variables and the like.

## Class Method Names

Class methods MUST be named in lowerCamelCase. Example: `def
processUsageData(self, input)`. Private functions (that are functions which
are not meant to be called from outside of the class or its descendants)
SHOULD be prefix with an underscore. Example: `def _myPrivateFn(self)`.

## File Names

Files names should not contain spaces. Ideally the should only contain
alphanumeric characters and `-_.`.

## String Formatting

The `%` operator should not be used. Instead, the python3 `.format()` function
should be used.
