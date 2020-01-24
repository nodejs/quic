#include "node_sockaddr-inl.h"
#include "gtest/gtest.h"

using node::SocketAddress;

TEST(SocketAddress, SocketAddress) {
  CHECK(SocketAddress::is_numeric_host("123.123.123.123"));
  CHECK(!SocketAddress::is_numeric_host("localhost"));

  sockaddr_storage storage;
  sockaddr_storage storage2;
  SocketAddress::ToSockAddr(AF_INET, "123.123.123.123", 443, &storage);
  SocketAddress::ToSockAddr(AF_INET, "1.1.1.1", 80, &storage2);

  SocketAddress addr(reinterpret_cast<const sockaddr*>(&storage));
  SocketAddress addr2(reinterpret_cast<const sockaddr*>(&storage2));

  CHECK_EQ(addr.length(), sizeof(sockaddr_in));
  CHECK_EQ(addr.family(), AF_INET);
  CHECK_EQ(addr.address(), "123.123.123.123");
  CHECK_EQ(addr.port(), 443);

  CHECK(!SocketAddress::Compare()(addr, addr2));
  CHECK(SocketAddress::Compare()(addr, addr));

  CHECK_EQ(SocketAddress::Hash()(addr), SocketAddress::Hash()(addr));
  CHECK_NE(SocketAddress::Hash()(addr), SocketAddress::Hash()(addr2));

  addr.Update(reinterpret_cast<uint8_t*>(&storage2), sizeof(sockaddr_in));
  CHECK_EQ(addr.length(), sizeof(sockaddr_in));
  CHECK_EQ(addr.family(), AF_INET);
  CHECK_EQ(addr.address(), "1.1.1.1");
  CHECK_EQ(addr.port(), 80);

  SocketAddress::Map<size_t> map;
  map[addr]++;
  map[addr]++;
  CHECK_EQ(map[addr], 2);
}
