package ru.tapublog.lib.gsm0348.impl;

import org.apache.log4j.Logger;
import ru.tapublog.lib.gsm0348.api.PacketBuilder;
import ru.tapublog.lib.gsm0348.api.PacketBuilderConfiguration;
import ru.tapublog.lib.gsm0348.api.PacketBuilderConfigurationException;

/**
 * Trivial {@linkplain PacketBuilder} factory. It creates new
 * {@linkplain PacketBuilder} for each {@linkplain PacketBuilderConfiguration}.
 * 
 * @author Victor Platov
 */
public class PacketBuilderFactory
{
	private static final Logger LOGGER = Logger.getLogger(PacketBuilderFactory.class);

	private PacketBuilderFactory()
	{
	}

	public static PacketBuilder getInstance(PacketBuilderConfiguration builderConfig) throws PacketBuilderConfigurationException
	{
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Creating new PacketBuilder for " + builderConfig);
		return new PacketBuilderImpl(builderConfig);
	}
}
