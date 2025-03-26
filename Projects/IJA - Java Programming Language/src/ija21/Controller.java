/*
  Class Controller
  @author Ladislav Dokoupil (xdokou14)
  @author Adrián Bobola (xbobol00)
 */

package ija21;

import javafx.scene.layout.Pane;
import java.util.*;

public class Controller {

    Pane root;
    JsonParser jsonParser;
    Map<String, Integer> requirements;
    int maxX, maxY;
    int scale;
    FindPath findPath;
    Timer timer;
    TimerTask mainLoop;

    /**
     * Create new controller for scene
     * @param root         - scene Pane
     * @param jsonParser   - parsed shelves
     * @param requirements - parsed requirements
     * @param scale        - scale of all objects
     */
    public Controller(Pane root, JsonParser jsonParser, Map<String, Integer> requirements, int scale) {
        this.root = root;
        this.jsonParser = jsonParser;
        this.requirements = requirements;
        this.maxX = jsonParser.getMaxX();
        this.maxY = jsonParser.getMaxY();
        this.scale = scale;
        //initialize pathfinding structure
        findPath = new FindPath(maxX, maxY, scale);
        timer = new Timer(false);
        mainLoop = new MainLoop(jsonParser, requirements, findPath);
    }

    /**
     * Default initialization of scene - remove existing objects from scene and add all new objects
     */
    public void resetObjects() {
        //removing existing objects from scene
        root.getChildren().removeAll(jsonParser.getEdges());
        root.getChildren().removeAll(jsonParser.getStages());
        root.getChildren().removeAll(getPaths(jsonParser.getAllShelfs()));
        root.getChildren().removeAll(jsonParser.getAllShelfs().values());
        root.getChildren().removeAll(jsonParser.getTrolleys());

        //put rectangle into edge of map
        root.getChildren().addAll(jsonParser.getEdges());
        //add staging areas for aesthetic reasons
        root.getChildren().addAll(jsonParser.getStages());
        //add paths
        root.getChildren().addAll(getPaths(jsonParser.getAllShelfs()));
        //add shelfs/obstacles/trolleys from file
        root.getChildren().addAll(jsonParser.getAllShelfs().values());
        root.getChildren().addAll(jsonParser.getTrolleys());

        //update every time shelfs are changed
        findPath.updatePaths(jsonParser.getAllShelfs());
    }

    /**
     * Set scene default values
     * @param mapSpeed - speed for changing scenes objects
     */
    public void start(int mapSpeed) {
        //set global scene variable so Shelfs/Trolleys can add their elements
        GlobalScene.pane = root;
        resetObjects();
        timer.scheduleAtFixedRate(mainLoop, 0, 10000 / mapSpeed);
    }

    /**
     * Pause scene
     */
    public void stop() {
        timer.cancel();
    }

    /**
     * Resume scene (if paused) or run new scene
     * @param mapSpeed - speed for changing scenes objects
     */
    public void play(int mapSpeed) {
        findPath.updatePaths(jsonParser.getAllShelfs());
        mainLoop = new MainLoop(jsonParser, requirements, findPath);
        timer = new Timer(false);
        timer.scheduleAtFixedRate(mainLoop, 0, 10000 / mapSpeed);
    }

    /**
     * Function get all paths
     * @param shelfs - Shelves attribute
     * @return - Array list of paths
     */
    public List<PathObject> getPaths(Map<Coordinates, Shelf> shelfs) {
        List<PathObject> paths = new ArrayList<>();
        //make new paths (complement of shelfs with respect to 0-maxX and 0-maxY)
        paths.clear();
        for (int x = 0; x <= jsonParser.getMaxX(); x += blockWidth.SCALE) {
            for (int y = 0; y <= jsonParser.getMaxY(); y += blockWidth.SCALE) {
                Coordinates position = new Coordinates(x, y);
                //is shelf
                if (shelfs.containsKey(position))
                    continue;
                PathObject n = new PathObject(position, this);
                paths.add(n);
            }
        }
        return paths;
    }
}
