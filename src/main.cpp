#include <iostream>
#include "TrapdoorHash.hpp"

#define TEST_SIZE 128

void ut_trapdoor_hash()
{
	std::cout << "UT tests for TrapdoorHash class" << std::endl;
	TrapdoorHash_DLA hash_dla;
	Botan::secure_vector<uint8_t> result;
	unsigned char msg[] = "test";
	unsigned int random_seed = 5767;
	std::cout << "Generated key: " << std::endl;
	hash_dla.generate_key(TEST_SIZE);
	hash_dla.debug_print();
	result = hash_dla.hash(msg, sizeof(msg)+1, reinterpret_cast<uint8_t*>(&random_seed), sizeof(random_seed));
}

// Just a simple file with functionality of future library
int main()
{
	std::cout << "THF template started" << std::endl; 
	ut_trapdoor_hash();
	std::cout << "THF template finished" << std::endl; 
}