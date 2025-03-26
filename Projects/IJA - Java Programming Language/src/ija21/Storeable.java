/*
  Class Storeable
  @author Ladislav Dokoupil (xdokou14)
  @author Adrián Bobola (xbobol00)
 */

package ija21;

import java.util.HashMap;
import java.util.Map;

public abstract class Storeable extends Coordinates {
    private Map<String, Integer> stored = new HashMap<>();

    public Storeable(Coordinates cord, int R, int G, int B) {
        super(cord, R, G, B);
    }

    /**
     * Adds tuple name-count to stored items list
     *
     * @param name  name of goods to be stored
     * @param count amount of goods to be stored
     */
    public void add_item(String name, int count) {
        if (count > 0) {
            int storedCount = stored.getOrDefault(name, 0);
            stored.put(name, storedCount + count);
        }
    }

    /**
     * Removes count of good from shelf
     *
     * @param name  name of goods to be removed
     * @param count amount of goods to be removed
     * @return amount of goods actually removed
     */
    public int delete_item(String name, int count) {
        int storedCount = stored.getOrDefault(name, 0);
        //some items remain in object
        if (storedCount > count) {
            stored.put(name, storedCount - count);
            return count;
        } else {
            stored.remove(name);
            return storedCount;
        }
    }

    public Map<String, Integer> getStored() {
        return stored;
    }
}
