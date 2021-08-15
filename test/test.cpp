/**
 * General purposed file to create some testing tool to fond out 
 * correctness of realization
 */

#include <iostream>
#include "TrapdoorHash.hpp"

#define TEST_SIZE 128

void ut_trapdoor_hash()
{
	std::cout << "UT tests for TrapdoorHash class" << std::endl;
	TrapdoorHash_DLA hash_dla; 
	unsigned char msg[] = "test";
	unsigned int random_seed = 5767; 
	std::cout << "Generated key: " << std::endl;
	hash_dla.generate_key(TEST_SIZE);
	hash_dla.debug_print();
	hash_dla.hash(msg, sizeof(msg), reinterpret_cast<uint8_t*>(&random_seed), sizeof(random_seed));
}

int main(int argc, char* argv[])
{
	int command = 0;
	while(1)
	{
		std::cout << "Enter command code: ";
		std::cin >> command; 
		if (command == 0) { ut_trapdoor_hash(); }
		else if (command == 1) { /* smth else */}
		else if (command == 404) { break; }
		else { std::cout << "Unknown command" << std::endl; }
	}
}