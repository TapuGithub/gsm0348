package ru.tapublog.lib.gsm0348.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ru.tapublog.lib.gsm0348.api.PacketBuilder;
import ru.tapublog.lib.gsm0348.api.PacketBuilderConfigurationException;
import ru.tapublog.lib.gsm0348.api.model.CardProfile;

/**
 * Trivial {@linkplain PacketBuilder} factory. It creates new
 * {@linkplain PacketBuilder} for each {@linkplain CardProfile}.
 * 
 * @author Victor Platov
 */
public class PacketBuilderFactory
{
	private static final Logger LOGGER = LoggerFactory.getLogger(PacketBuilderFactory.class);

	private PacketBuilderFactory()
	{

	}

	public static PacketBuilder getInstance(CardProfile cardProfile) throws PacketBuilderConfigurationException
	{
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Creating new PacketBuilder for " + cardProfile);

		return new PacketBuilderImpl(cardProfile);
	}
}
