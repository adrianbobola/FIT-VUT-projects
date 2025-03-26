/*
  @author Ladislav Dokoupil (xdokou14)
  @author Adrián Bobola (xbobol00)
 */

package ija21;

import java.util.*;

public class MainLoop extends TimerTask {

    JsonParser jsonParser;
    Map<String, Integer> requirements;
    FindPath findPath;

    public MainLoop(JsonParser jsonParser, Map<String, Integer> requirements, FindPath findPath) {
        this.jsonParser = jsonParser;
        this.requirements = requirements;
        this.findPath = findPath;
    }

    /**
     * core of algorithm.
     * every tick of timer runs task on all trolleys.
     */
    @Override
    public void run() {
        //iterate trolleys
        for (Trolley trolley : jsonParser.getTrolleys()) {
            //unload goods

            if ((trolley.getRemainCapacity() == 0 || (trolley.task == null && trolley.getItemInCount() > 0)) && !trolley.unload) {
                trolley.unload = true;
                trolley.pathList = null;
            }

            //set task to empty trolleys
            if (trolley.task == null && requirements.size() > 0) {
                Map.Entry<String, Integer> tmp;
                tmp = requirements.entrySet().iterator().next();
                trolley.task = new AbstractMap.SimpleEntry<>(tmp.getKey(), tmp.getValue());
                requirements.remove(tmp.getKey());
            }
            //ending condition
            if (requirements.size() == 0 && jsonParser.getTrolleys().stream().allMatch(trolley1 -> trolley1.task == null)
                    && jsonParser.getTrolleys().stream().allMatch(trolley1 -> trolley1.getItemInCount() == 0)) {
                //all trolleys finished
                this.cancel();
                return;
            } else if (requirements.size() == 0 && trolley.task == null && !trolley.unload) {
                //wait for other to finish
                continue;
            }

            //sort shelfs by distance
            TreeMap<Double, Coordinates> sortedByDistances = new TreeMap<>();

            //path to unload
            if (trolley.unload) {
                // shelves with stages sorted by distance
                for (Coordinates entry : jsonParser.getStages()) {
                    double distance = entry.getDistance(trolley);
                    sortedByDistances.put(distance, entry);
                }
            } else { // path to shelves
                Map<Coordinates, Shelf> found = jsonParser.findGoods(trolley.task.getKey());
                for (Map.Entry<Coordinates, Shelf> entry : found.entrySet()) {
                    double distance = entry.getKey().getDistance(trolley);
                    sortedByDistances.put(distance, entry.getKey());
                }
            }

            if (trolley.pathList == null) {
                //iterate all coordinates if some are unavailable and compute path
                Coordinates currentCoordinates = new Coordinates((int) trolley.getX(), (int) trolley.getY());
                trolley.pathList = null;
                Collection<Coordinates> tmp = sortedByDistances.values();
                for (Coordinates cord : tmp) {
                    trolley.pathList = findPath.aStar(currentCoordinates, cord);
                    trolley.location = cord;
                    if (trolley.pathList != null)
                        break;
                    else
                        trolley.location = null;
                }
            }

            if (trolley.pathList == null) {
                System.err.println("!!!!!!! ERROR: LOCATION UNAVAILABLE !!!!!!!!!");
                if (trolley.unload) {
                    System.exit(1);
                }
                trolley.task = null;
                trolley.pathList = null;
                trolley.location = null;
                continue;
            }

            if (trolley.pathList.size() != 0) {
                //move trolley
                trolley.setX(trolley.pathList.get(0).getX());
                trolley.setY(trolley.pathList.get(0).getY());
                trolley.pathList.remove(0);
            } else if (!trolley.unload) {
                //next to shelf- load goods = remove items from shelf and add to trolley
                Shelf itemShelf = jsonParser.getAllShelfs().get(trolley.location);
                //count of items to delete - with respect to max capacity
                int deleteCount = Math.min(trolley.getRemainCapacity(), trolley.task.getValue());
                int removedItem = itemShelf.delete_item(trolley.task.getKey(), deleteCount);
                trolley.task.setValue(trolley.task.getValue() - removedItem);
                trolley.add_item(trolley.task.getKey(), removedItem);
                trolley.pathList = null;
                //Deleted OK - set task = nul;
                if (trolley.task.getValue() == 0)
                    trolley.task = null;
            } else {
                //next to stage - unload
                trolley.pathList = null;
                trolley.unloadGoods();
            }
        }
    }
}
