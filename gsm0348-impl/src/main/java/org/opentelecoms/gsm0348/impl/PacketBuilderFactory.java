package org.opentelecoms.gsm0348.impl;

import org.opentelecoms.gsm0348.api.PacketBuilder;
import org.opentelecoms.gsm0348.api.PacketBuilderConfigurationException;
import org.opentelecoms.gsm0348.api.model.CardProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Trivial {@linkplain PacketBuilder} factory. It creates new
 * {@linkplain PacketBuilder} for each {@linkplain CardProfile}.
 *
 * @author Victor Platov
 */
public class PacketBuilderFactory {
  private static final Logger LOGGER = LoggerFactory.getLogger(PacketBuilderFactory.class);

  private PacketBuilderFactory() {

  }

  public static PacketBuilder getInstance(CardProfile cardProfile) throws PacketBuilderConfigurationException {
    LOGGER.debug("Creating new PacketBuilder for " + cardProfile);
    return new PacketBuilderImpl(cardProfile);
  }
}
