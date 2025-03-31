import greenfoot.*;  // (World, Actor, GreenfootImage, Greenfoot and MouseInfo)

/**
 * Write a description of class InstructionsMenu here.
 * 
 * @author (your name) 
 * @version (a version number or a date)
 */
public class InstructionsMenu extends World
{

    /**
     * Constructor for objects of class InstructionsMenu.
     * 
     */
    public InstructionsMenu()
    {    
        super(1000, 700, 1);
        nextArrow arrow1 = new nextArrow();
        addObject(arrow1,945,645);

        String instructionsText = "As you can see, you have a bomb that's rigged to go off \n" +
                                  "the only way to disarm it is by solving 3 puzzles before \n" +
                                  "the timer runouts and the bomb explodes! If you lose on a \n"+
                                  "minigame the timer will go down on time but if you win the time goes up";

        showText(instructionsText, getWidth() / 2, getHeight() / 2); // Display the instructions text at the center of the world

    }
}
