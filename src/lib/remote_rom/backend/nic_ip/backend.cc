/*
 * \brief  TODO
 * \author Johannes Schlatow
 * \date   2016-02-18
 */

#include <base/env.h>
#include <base/exception.h>
#include <base/log.h>
#include <base/attached_rom_dataspace.h>

#include <backend_base.h>

#include <nic/packet_allocator.h>
#include <nic_session/connection.h>

#include <net/ethernet.h>
#include <net/ipv4.h>

namespace Remote_rom {
	bool verbose = false;
	using  Genode::size_t;
	using  Genode::uint16_t;
	using  Genode::uint32_t;
	using  Genode::Cstring;
	using  Genode::Packet_descriptor;
	using  Genode::env;
	using  Net::Ethernet_frame;
	using  Net::Ipv4_packet;
	using  Net::Mac_address;
	using  Net::Ipv4_address;
	using  Net::Size_guard;

	template <class>
	class  Backend_base;
	class  Backend_server;
	class  Backend_client;

	struct Packet;
	struct DataPacket;
};

/* Packet format we use for inter-system communication */
class Remote_rom::Packet
{
	public:
		enum {
			MAX_NAME_LEN = 64        /* maximum length of the module name */
		};

		typedef enum {
			SIGNAL    = 1,           /* signal that ROM content has changed     */
			UPDATE    = 2,           /* request transmission of updated content */
			DATA      = 3,           /* data packet                             */
		} Type;

	private:
		char         _module_name[MAX_NAME_LEN];   /* the ROM module name */
		Type         _type;                        /* packet type */

		/*****************************************************
		 ** 'payload' must be the last member of this class **
		 *****************************************************/

		char payload[0];

	public:
		/**
		 * Return type of the packet
		 */
		Type type() const { return _type; }

		/**
		 * Return module_name of the packet
		 */
		const char *module_name() { return _module_name; }

		void type(Type type)
		{
			_type = type;
		}

		void module_name(const char *module)
		{
			Genode::strncpy(_module_name, module, MAX_NAME_LEN);
		}

		template <typename T>
		T const &data(Size_guard &size_guard) const
		{
			size_guard.consume_head(sizeof(T));
			return *(T const *)(payload);
		}

		template <typename T>
		T &construct_at_data(Size_guard &size_guard)
		{
			size_guard.consume_head(sizeof(T));
			return *Genode::construct_at<T>(payload);
		}

} __attribute__((packed));


class Remote_rom::DataPacket
{
	public:
		enum { MAX_PAYLOAD_SIZE = 1024 };

	private:
		uint32_t     _content_size;                /* ROM content size in bytes */
		uint32_t     _offset;                      /* offset in bytes */
		uint16_t     _payload_size;                /* payload size in bytes */

		char payload[0];

	public:
		/**
		 * Return size of the packet
		 */
		size_t size() const { return _payload_size + sizeof(*this); }

		/**
		 * Return content_size of the packet
		 */
		size_t content_size() const { return _content_size; }

		/**
		 * Return offset of the packet
		 */
		size_t offset() const { return _offset; }

		void content_size(size_t size) { _content_size = size; }
		void offset(size_t offset) { _offset = offset; }

		/**
		 * Set payload size of the packet
		 */
		void payload_size(Genode::size_t payload_size)
		{
			_payload_size = payload_size;
		}

		/**
		 * Return payload size of the packet
		 */
		size_t payload_size() const { return _payload_size; }

		/**
		 * Return address of the payload
		 */
		void *addr() { return payload; }
		const void *addr() const { return payload; }

		/**
		 * Return packet size for given payload 
		 */
		static size_t packet_size(size_t payload) { return sizeof(DataPacket) + Genode::min(payload, MAX_PAYLOAD_SIZE); }

} __attribute__((packed));

template <class HANDLER>
class Remote_rom::Backend_base
{
	protected:
		enum {
			PACKET_SIZE = 1024,
			BUF_SIZE = Nic::Session::QUEUE_SIZE * PACKET_SIZE
		};

		class Rx_thread : public Genode::Thread
		{
			protected:
				Ipv4_address    &_accept_ip;
				Nic::Connection &_nic;
				HANDLER         &_handler;

				Genode::Signal_receiver              _sig_rec;
				Genode::Signal_dispatcher<Rx_thread> _link_state_dispatcher;
				Genode::Signal_dispatcher<Rx_thread> _rx_packet_avail_dispatcher;
				Genode::Signal_dispatcher<Rx_thread> _rx_ready_to_ack_dispatcher;

				void _handle_rx_packet_avail(unsigned)
				{
					while (_nic.rx()->packet_avail() && _nic.rx()->ready_to_ack()) {
						Packet_descriptor _rx_packet = _nic.rx()->get_packet();

						char *content = _nic.rx()->packet_content(_rx_packet);
						Size_guard edguard(_rx_packet.size());
						Ethernet_frame &eth = Ethernet_frame::cast_from(content, edguard);

						/* check IP */
						Ipv4_packet &ip_packet = eth.data<Ipv4_packet>(edguard);
						if (_accept_ip == Ipv4_packet::broadcast() || _accept_ip == ip_packet.dst())
							_handler.receive(ip_packet.data<Packet>(edguard), edguard);

						_nic.rx()->acknowledge_packet(_rx_packet);
					}
				}

				void _handle_rx_ready_to_ack(unsigned) { _handle_rx_packet_avail(0); }

				void _handle_link_state(unsigned)
				{
					Genode::log("link state changed");
				}

			public:
				Rx_thread(Nic::Connection &nic, HANDLER &handler, Ipv4_address &ip)
				: Genode::Thread(Weight::DEFAULT_WEIGHT, "backend_nic_rx", 8192),
				  _accept_ip(ip),
				  _nic(nic), _handler(handler),
				  _link_state_dispatcher(_sig_rec, *this, &Rx_thread::_handle_link_state),
				  _rx_packet_avail_dispatcher(_sig_rec, *this, &Rx_thread::_handle_rx_packet_avail),
				  _rx_ready_to_ack_dispatcher(_sig_rec, *this, &Rx_thread::_handle_rx_ready_to_ack)
				{
					_nic.link_state_sigh(_link_state_dispatcher);
					_nic.rx_channel()->sigh_packet_avail(_rx_packet_avail_dispatcher);
					_nic.rx_channel()->sigh_ready_to_ack(_rx_ready_to_ack_dispatcher);
				} 

				void entry()
				{
					while(true)
					{
						Genode::Signal sig = _sig_rec.wait_for_signal();
						int num    = sig.num();

						Genode::Signal_dispatcher_base *dispatcher;
						dispatcher = dynamic_cast<Genode::Signal_dispatcher_base *>(sig.context());
						dispatcher->dispatch(num);
					}
				}
		};

		Nic::Packet_allocator _tx_block_alloc;
		Nic::Connection       _nic;
		Rx_thread             _rx_thread;
		Mac_address           _mac_address;
		Ipv4_address          _src_ip;
		Ipv4_address          _accept_ip;
		Ipv4_address          _dst_ip;

	protected:
		void _tx_ack(bool block = false)
		{
			/* check for acknowledgements */
			while (_nic.tx()->ack_avail() || block) {
				Nic::Packet_descriptor acked_packet = _nic.tx()->get_acked_packet();
				_nic.tx()->release_packet(acked_packet);
				block = false;
			}
		}

		Ipv4_packet &_prepare_upper_layers(void *base, Size_guard &size_guard)
		{
			Ethernet_frame &eth = Ethernet_frame::construct_at(base, size_guard);
			eth.src(_mac_address);
			eth.dst(Ethernet_frame::broadcast());
			eth.type(Ethernet_frame::Type::IPV4);

			Ipv4_packet &ip = eth.construct_at_data<Ipv4_packet>(size_guard);
			ip.version(4);
			ip.header_length(5);
			ip.time_to_live(10);
			ip.src(_src_ip);
			ip.dst(_dst_ip);

			return ip;
		}

		size_t _upper_layer_size(size_t size)
		{
			return sizeof(Ethernet_frame) + sizeof(Ipv4_packet) + size;
		}

		void _finish_ipv4(Ipv4_packet &ip, size_t payload)
		{
			ip.total_length(sizeof(ip) + payload);
			ip.update_checksum();
		}

		template <typename T>
		void _transmit_notification_packet(Packet::Type type, T *frontend)
		{
			size_t frame_size = _upper_layer_size(sizeof(Packet));
			Nic::Packet_descriptor pd = alloc_tx_packet(frame_size);
			Size_guard size_guard(pd.size());

			char *content = _nic.tx()->packet_content(pd);
			Ipv4_packet &ip = _prepare_upper_layers(content, size_guard);
			Packet &pak = ip.construct_at_data<Packet>(size_guard);
			pak.type(type);
			pak.module_name(frontend->module_name());
			_finish_ipv4(ip, sizeof(Packet));

			submit_tx_packet(pd);
		}

	public:
		explicit Backend_base(Genode::Env &env, Genode::Allocator &alloc, HANDLER &handler)
		:
			_tx_block_alloc(&alloc), _nic(env, &_tx_block_alloc, BUF_SIZE, BUF_SIZE),
			_rx_thread(_nic, handler, _accept_ip)
		{
			/* start dispatcher thread */
			_rx_thread.start();

			/* store mac address */
			_mac_address = _nic.mac_address();

			Genode::Attached_rom_dataspace config = {env, "config"};

			try {
				char ip_string[15];
				Genode::Xml_node remoterom = config.xml().sub_node("remote_rom");
				remoterom.attribute("src").value(ip_string, sizeof(ip_string));
				_src_ip = Ipv4_packet::ip_from_string(ip_string);

				remoterom.attribute("dst").value(ip_string, sizeof(ip_string));
				_dst_ip = Ipv4_packet::ip_from_string(ip_string);

				_accept_ip = _src_ip;
			} catch (...) {
				Genode::warning("No IP configured, falling back to broadcast mode!");
				_src_ip = Ipv4_packet::current();
				_dst_ip = Ipv4_packet::broadcast();
				_accept_ip = Ipv4_packet::broadcast();
			}
		}

		Nic::Packet_descriptor alloc_tx_packet(Genode::size_t size)
		{
			while (true) {
				try {
					Nic::Packet_descriptor packet = _nic.tx()->alloc_packet(size);
					return packet;
				} catch(Nic::Session::Tx::Source::Packet_alloc_failed) {
					/* packet allocator exhausted, wait for acknowledgements */
					_tx_ack(true);
				}
			}
		}

		void submit_tx_packet(Nic::Packet_descriptor packet)
		{
			_nic.tx()->submit_packet(packet);
			/* check for acknowledgements */
			_tx_ack();
		}
};

class Remote_rom::Backend_server : public Backend_server_base, public Backend_base<Backend_server>
{
	private:
		Rom_forwarder_base         *_forwarder;

		void send_data()
		{
			if (!_forwarder) return;

			size_t offset = 0;
			size_t size = _forwarder->content_size();
			while (offset < size)
			{
				/* create and transmit packet via NIC session */
				size_t max_size = _upper_layer_size(sizeof(Packet)
				                                    + DataPacket::packet_size(size));
				Nic::Packet_descriptor pd = alloc_tx_packet(max_size);
				Size_guard size_guard(pd.size());

				char *content = _nic.tx()->packet_content(pd);
				Ipv4_packet &ip = _prepare_upper_layers(content, size_guard);
				Packet &pak = ip.construct_at_data<Packet>(size_guard);
				pak.type(Packet::DATA);
				pak.module_name(_forwarder->module_name());

				DataPacket &data = pak.construct_at_data<DataPacket>(size_guard);
				data.offset(offset);
				data.content_size(size);

				data.payload_size(_forwarder->transfer_content((char*)data.addr(), DataPacket::MAX_PAYLOAD_SIZE, offset));
				_finish_ipv4(ip, sizeof(Packet) + data.size());

				submit_tx_packet(pd);

				offset += data.payload_size();
			}
		}

	public:
		Backend_server(Genode::Env &env, Genode::Allocator &alloc) : Backend_base(env, alloc, *this), _forwarder(nullptr)
		{	}

		void register_forwarder(Rom_forwarder_base *forwarder)
		{
			_forwarder = forwarder;
		}

		void send_update()
		{
			if (!_forwarder) return;
			_transmit_notification_packet(Packet::SIGNAL, _forwarder);
		}

		void receive(Packet &packet, Size_guard &size_guard)
		{
			switch (packet.type())
			{
				case Packet::UPDATE:
					if (verbose)
						Genode::log("receiving UPDATE (", Cstring(packet.module_name()), ") packet");

					if (!_forwarder)
						return;

					/* check module name */
					if (Genode::strcmp(packet.module_name(), _forwarder->module_name()))
						return;

					/* TODO (optional) dont send data within Rx_Thread's context */
					send_data();
					
					break;
				default:
					break;
			}
		}
};

class Remote_rom::Backend_client : public Backend_client_base, public Backend_base<Backend_client>
{
	private:
		Rom_receiver_base          *_receiver;
		char                       *_write_ptr;
		size_t                     _buf_size;


		void write(const void *data, size_t offset, size_t size)
		{
			if (!_write_ptr) return;


			size_t const len = Genode::min(size, _buf_size-offset);
			Genode::memcpy(_write_ptr+offset, data, len);

			if (offset + len >= _buf_size)
				_receiver->commit_new_content();
		}

	public:
		Backend_client(Genode::Env &env, Genode::Allocator &alloc) : Backend_base(env, alloc, *this), _receiver(nullptr), _write_ptr(nullptr), _buf_size(0)
		{
		}

		void register_receiver(Rom_receiver_base *receiver)
		{
			/* TODO support multiple receivers (ROM names) */
			_receiver = receiver;

			/* FIXME request update on startup (occasionally triggers invalid signal-context capability) */
//			if (_receiver)
//				update(_receiver->module_name());
		}


		void update(const char* module_name)
		{
			if (!_receiver) return;

			/* check module name */
			if (Genode::strcmp(module_name, _receiver->module_name()))
				return;

			_transmit_notification_packet(Packet::UPDATE, _receiver);
		}

		void receive(Packet &packet, Size_guard &size_guard)
		{
			switch (packet.type())
			{
				case Packet::SIGNAL:
					if (verbose)
						Genode::log("receiving SIGNAL(", Cstring(packet.module_name()), ") packet");

					/* send update request */
					update(packet.module_name());
					
					break;
				case Packet::DATA:
					{
						if (verbose)
							Genode::log("receiving DATA(", Cstring(packet.module_name()), ") packet");

						/* write into buffer */
						if (!_receiver) return;

						/* check module name */
						if (Genode::strcmp(packet.module_name(), _receiver->module_name()))
							return;

						const DataPacket &data = packet.data<DataPacket>(size_guard);
						size_guard.consume_head(data.payload_size());

						if (!data.offset()) {
							_write_ptr = _receiver->start_new_content(data.content_size());
							_buf_size  = (_write_ptr) ? data.content_size() : 0;
						}

						write(data.addr(), data.offset(), data.payload_size());

						break;
					}
				default:
					break;
			}
		}
};

Remote_rom::Backend_server_base &Remote_rom::backend_init_server(Genode::Env &env, Genode::Allocator &alloc)
{
	static Backend_server backend(env, alloc);
	return backend;
}

Remote_rom::Backend_client_base &Remote_rom::backend_init_client(Genode::Env &env, Genode::Allocator &alloc)
{
	static Backend_client backend(env, alloc);
	return backend;
}
