class ItemService {
  constructor() {
    // Check if an instance already exists
    if (!ItemService.instance) {
      ItemService.instance = this;
    }
    return ItemService.instance;
  }

  // Method to create an item (e.g., add an item to inventory)
  createItem(name, category, quantity) {
    // Logic for creating an item
    console.log(`Creating item: ${name} (${category}, ${quantity})`);
    // Add more logic here if needed to interact with the database
  }

  // Example method to fetch all items
  getAllItems() {
    console.log("Fetching all items...");
    // Add logic to fetch items from the database
  }
}

// Create and freeze the singleton instance
const instance = new ItemService();
Object.freeze(instance);

module.exports = instance; // Export the instance so it can be used elsewhere in the app
