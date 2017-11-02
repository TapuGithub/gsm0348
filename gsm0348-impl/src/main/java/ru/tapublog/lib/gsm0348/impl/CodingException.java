package ru.tapublog.lib.gsm0348.impl;

import ru.tapublog.lib.gsm0348.api.Gsm0348Exception;

public class CodingException extends Gsm0348Exception
{
	private static final long serialVersionUID = 1L;

	public CodingException()
	{
	}

	public CodingException(String message)
	{
		super(message);
	}

	public CodingException(Throwable cause)
	{
		super(cause);
	}

	public CodingException(String message, Throwable cause)
	{
		super(message, cause);
	}
}
