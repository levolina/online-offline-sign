#include <iostream>
#include "TrapdoorHash.hpp"

#define TEST_SIZE 128

void ut_trapdoor_hash()
{
	TH_PrivateKey private_key(251387, 62849, 36711, 31862); 
	private_key.print(); 

	int test = 64; 
	uint8_t* test_ptr = reinterpret_cast<uint8_t*>(&test);
	std::vector<uint8_t> test_vector(test_ptr, test_ptr + sizeof(int));
	char buffer[] = "msg";
	uint8_t* buffer_ptr = reinterpret_cast<uint8_t*>(buffer);
	std::vector<uint8_t> test2(buffer_ptr, buffer_ptr + sizeof(buffer));

	private_key.hash(test_vector, 25);
	Botan::BigInt r2 = private_key.collision(test_vector, 25, test2);
}

// Just a simple file with functionality of future library
int main()
{
	std::cout << "THF template started" << std::endl; 
	ut_trapdoor_hash();
	std::cout << "THF template finished" << std::endl; 
}