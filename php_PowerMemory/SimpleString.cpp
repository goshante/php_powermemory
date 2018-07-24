#include "defs.h"
#include "SimpleString.h"
#include <string.h>

String::String()
{
	m_size = 0;
	clear();
}

String::String(const char* str)
{
	m_size = strlen(str) + 1;
	m_buffer = new char[m_size];
	strcpy_s(m_buffer, m_size, str);
}

String::String(const String& cpy)
{
	m_size = cpy.m_size;
	m_buffer = new char[m_size];
	strcpy_s(m_buffer, m_size, cpy.m_buffer);
}

String::~String()
{
	if (m_size > 0)
		delete[] m_buffer;
}

void String::_append(const char* str)
{
	char* prev = m_buffer;
	size_t len = strlen(str);
	size_t newSize = m_size + len;
	m_buffer = new char[newSize];

	strcpy_s(m_buffer, newSize, prev);
	strcpy_s(m_buffer + strlen(m_buffer), newSize - strlen(m_buffer), str);
	m_buffer[newSize - 1] = '\0';

	if (m_size > 0)
		delete[] prev;
	m_size = newSize;
}

size_t String::size() const
{
	return m_size;
}

size_t String::length() const
{
	if (m_size > 0)
		return strlen(m_buffer);
	else
		return 0;
}

char String::at(size_t i) const
{
	return m_buffer[i];
}

String& String::operator=(const char* str)
{
	m_size = strlen(str) + 1;
	m_buffer = new char[m_size];
	strcpy_s(m_buffer, m_size, str);
	return *this;
}

String& String::operator=(const String& cpy)
{
	m_size = cpy.m_size;
	m_buffer = new char[m_size];
	strcpy_s(m_buffer, m_size, cpy.m_buffer);
	return *this;
}
String& String::operator+=(const char* str)
{
	_append(str);
	return *this;
}

String& String::operator+=(const String& cpy)
{
	_append(cpy.m_buffer);
	return *this;
}

char& String::operator[](size_t i)
{
	return m_buffer[i];
}

char& String::operator[](int i)
{
	return m_buffer[i];
}

void String::clear()
{
	if (m_size > 0)
		delete[] m_buffer;
	m_size = 1;
	m_buffer = new char[1];
	m_buffer = '\0';
}

void String::push_back(char c)
{
	char* prev = m_buffer;
	size_t newSize = m_size + 1;
	m_buffer = new char[newSize];

	strcpy_s(m_buffer, newSize, prev);
	m_buffer[newSize - 1] = '\0';
	m_buffer[newSize - 2] = c;

	if (m_size > 0)
		delete[] prev;
	m_size = newSize;
}

void String::resize(size_t size, char c)
{
	clear();
	m_size = size + 1;
	m_buffer = new char[m_size];

	for (size_t i = 0; i < m_size; i++)
		m_buffer[i] = c;
}

void String::Append(const char* str)
{
	_append(str);
}

void String::Append(const String& str)
{
	_append(str.m_buffer);
}

const char* String::c_str() const
{
	return const_cast<const char*>(m_buffer);
}

String::operator const char*() const
{
	return c_str();
}

bool operator==(const String& left, const char* right)
{
	if (strcmp(left.m_buffer, right))
		return false;
	else
		return true;
}

bool operator!=(const String& left, const char* right)
{
	if (strcmp(left.m_buffer, right))
		return true;
	else
		return false;
}

bool operator==(const String& left, const String& right)
{
	if (strcmp(left.m_buffer, right.m_buffer))
		return false;
	else
		return true;
}

bool operator!=(const String& left, const String& right)
{
	if (strcmp(left.m_buffer, right.m_buffer))
		return true;
	else
		return false;
}

String operator+(String& left, const char* right)
{
	left += right;
	return left;
}

String operator+(String& left, const String& right)
{
	left += right;
	return left;
}