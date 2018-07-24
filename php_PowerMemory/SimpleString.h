#pragma once

class String
{
private:
	char* m_buffer;
	size_t m_size;

	void _append(const char* str);

public:
	String();
	String(const char* str);
	String(const String& cpy);
	~String();

	size_t size() const;
	size_t length() const;
	char at(size_t i) const;

	String& operator=(const char* str);
	String& operator=(const String& cpy);
	String& operator+=(const char* str);
	String& operator+=(const String& cpy);
	char& operator[](size_t i);
	char& operator[](int i);

	void clear();
	void push_back(char c);
	void resize(size_t size, char c = '\0');
	void Append(const char* str);
	void Append(const String& str);

	friend bool operator==(const String& left, const char* right);
	friend bool operator!=(const String& left, const char* right);

	friend bool operator==(const String& left, const String& right);
	friend bool operator!=(const String& left, const String& right);

	friend String operator+(String& left, const char* right);
	friend String operator+(String& left, const String& right);

	const char* c_str() const;
	operator const char*() const;
};

