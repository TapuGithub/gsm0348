package ru.tapublog.lib.gsm0348.impl;

import javax.annotation.concurrent.Immutable;

import ru.tapublog.lib.gsm0348.api.header.commandpacket.CommandSPI;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.ResponseSPI;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.SPI;

/**
 * @author Victor Platov
 */
@Immutable
public final class SPIImpl implements SPI
{
	private final CommandSPI m_commandSPI;
	private final ResponseSPI m_responseSPI;

	public SPIImpl(CommandSPI commandSPI, ResponseSPI responseSPI)
	{
		if (commandSPI == null || responseSPI == null)
			throw new IllegalArgumentException("commandSPI and responseSPI cannot be null");

		m_commandSPI = commandSPI;
		m_responseSPI = responseSPI;
	}

	public CommandSPI getCommandSPI()
	{
		return m_commandSPI;
	}

	public ResponseSPI getResponseSPI()
	{
		return m_responseSPI;
	}

	public String toString()
	{
		return "SPI[commandSPI=" + getCommandSPI() + ", responseSPI=" + getResponseSPI() + "]";
	}

	public boolean equals(Object obj)
	{
		if (this == obj)
			return true;
		if (!(obj instanceof SPIImpl))
			return false;
		SPIImpl spii = (SPIImpl) obj;
		return getCommandSPI().equals(spii.getCommandSPI()) && getResponseSPI().equals(spii.getResponseSPI());
	}

	public int hashCode()
	{
		int result = 42;
		result = 37 * result + getCommandSPI().hashCode();
		result = 37 * result + getResponseSPI().hashCode();
		return result;
	}
}
