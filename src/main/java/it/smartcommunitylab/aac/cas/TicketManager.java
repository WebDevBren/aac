/*******************************************************************************
 * Copyright 2015 Fondazione Bruno Kessler
 * 
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 * 
 *        http://www.apache.org/licenses/LICENSE-2.0
 * 
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 ******************************************************************************/

package it.smartcommunitylab.aac.cas;

import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.stereotype.Component;

import it.smartcommunitylab.aac.cas.CASException.ERROR_CODE;

/**
 * @author raman
 *
 */
@Component
public class TicketManager {

	private RandomValueStringGenerator generator = new RandomValueStringGenerator();
	
	private ConcurrentHashMap<TicketKey, Ticket> ticketStorage = new ConcurrentHashMap<TicketManager.TicketKey, TicketManager.Ticket>();
	private ConcurrentHashMap<String, Ticket> ticketKeyStorage = new ConcurrentHashMap<String, TicketManager.Ticket>();
	private static final long TICKET_VALIDITY = 1000*60*60*24;
	
	/**
	 * @param id
	 * @param service 
	 * @return 
	 */
	public String getTicket(String id, String service) {
		TicketKey key = new TicketKey(id, service);
		Ticket ticket = ticketStorage.get(key);
		if (ticket == null || ticket.isExpired()) {
			boolean fromNew = true;
			for (Ticket t : ticketStorage.values()) {
				if (t.id.equals(id) && !t.isExpired()) {
					fromNew = false;
					break;
				}
			}
			ticket = new Ticket(id, service, generateTicket(), fromNew);
			ticketStorage.put(key, ticket);
			ticketKeyStorage.put(ticket.ticket, ticket);
		}
		return ticket.ticket;
	}

	/**
	 * @return
	 */
	private String generateTicket() {
		return "ST-"+UUID.randomUUID().toString() + generator.generate(); 
	}

	/**
	 * @param string
	 * @param service
	 * @param ticket
	 * @return Ticket
	 */
	public Ticket checkTicket(String service, String ticket) throws CASException{
		Ticket ticketObj = ticketKeyStorage.get(ticket);
		if (ticketObj == null || ticketObj.isExpired()) throw new CASException(ERROR_CODE.INVALID_TICKET, "Ticket does not exists or is expired."); 
		if (!service.equals(ticketObj.service)) throw new CASException(ERROR_CODE.INVALID_SERVICE, "Service does not match ticket.");
		ticketStorage.remove(new TicketKey(ticketObj.id, service));
		ticketKeyStorage.remove(ticket);
		return ticketObj;
	}

	
	private static class TicketKey {
		private String id, service;

		public TicketKey(String id, String service) {
			super();
			this.id = id;
			this.service = service;
		}
		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((id == null) ? 0 : id.hashCode());
			result = prime * result
					+ ((service == null) ? 0 : service.hashCode());
			return result;
		}
		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			TicketKey other = (TicketKey) obj;
			if (id == null) {
				if (other.id != null)
					return false;
			} else if (!id.equals(other.id))
				return false;
			if (service == null) {
				if (other.service != null)
					return false;
			} else if (!service.equals(other.service))
				return false;
			return true;
		}
	}
	
	public static class Ticket {
		private String id, service, ticket;
		private long created;
		boolean fromNewLogin;
		
		public Ticket(String id, String service, String ticket, boolean fromNewLogin) {
			super();
			this.id = id;
			this.service = service;
			this.ticket = ticket;
			this.fromNewLogin = fromNewLogin;
			created = System.currentTimeMillis();
		}


		/**
		 * @return
		 */
		public boolean isExpired() {
			return System.currentTimeMillis()-TICKET_VALIDITY > created;
		}


		/**
		 * @return the id
		 */
		public String getId() {
			return id;
		}


		/**
		 * @return the service
		 */
		public String getService() {
			return service;
		}


		/**
		 * @return the ticket
		 */
		public String getTicket() {
			return ticket;
		}


		/**
		 * @return the created
		 */
		public long getCreated() {
			return created;
		}


		/**
		 * @return the fromNewLogin
		 */
		public boolean isFromNewLogin() {
			return fromNewLogin;
		}
		
	}
}
