/**
 * Copyright 2009, Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @fileoverview This file contains code that is common to several of the
 * manipulator samples, such as rotate1.html and translate2.html.
 *
 * This is purely *example* code, showing how to use the manipulators.
 *
 * Requires base.js
 */

o3djs.require('o3djs.util');
o3djs.require('o3djs.math');
o3djs.require('o3djs.quaternions');
o3djs.require('o3djs.rendergraph');
o3djs.require('o3djs.primitives');
o3djs.require('o3djs.manipulators');
o3djs.require('o3djs.effect');
o3djs.require('o3djs.cameracontroller');

// global variables
var g_o3dElement;
var g_client;
var g_o3d;
var g_math;
var g_mainPack;
var g_mainViewInfo;
var g_mainRoot;
var g_lightPosition = [5, 5, 7]; // TODO(simonrad): Remove this?
var g_lastCubeTransform;
var g_primitives = [];
var g_manager;
var g_cameraController;

/**
 * Creates the client area.
 */
function initClient() {
  window.g_finished = false;  // for selenium testing.

  // Runs the sample in V8. Comment out this line to run it in the browser
  // JavaScript engine, for example if you want to debug it.
  // TODO(kbr): we need to investigate why turning this on is
  //     significantly slower than leaving it disabled.
  // o3djs.util.setMainEngine(o3djs.util.Engine.V8);

  o3djs.util.makeClients(main);
}

/**
 * Initializes global variables, positions camera, draws shapes.
 * @param {Array} clientElements Array of o3d object elements.
 */
function main(clientElements) {
  var o3dElement = clientElements[0];

  // Init global variables.
  initGlobals(clientElements);

  // Add the shapes to the transform hierarchy.
  createShapes();

  // Add the manipulators to the transform hierarchy.
  setupManipulators();

  // Set up the view and projection transformations.
  initContext();

  // Start picking; it won't do anything until the scene finishes loading.
  o3djs.event.addEventListener(o3dElement, 'mousedown', onMouseDown);
  o3djs.event.addEventListener(o3dElement, 'mousemove', onMouseMove);
  o3djs.event.addEventListener(o3dElement, 'mouseup', onMouseUp);

  window.g_finished = true;  // for selenium testing.
}

function onMouseDown(e) {
  if(e.button == 2 && !e.shiftKey && !e.ctrlKey) {
    g_cameraController.setDragMode(
        o3djs.cameracontroller.DragMode.SPIN_ABOUT_CENTER, e.x, e.y);
  } else if(e.button == 2 && e.shiftKey && !e.ctrlKey) {
    g_cameraController.setDragMode(
        o3djs.cameracontroller.DragMode.ZOOM_IN_OUT, e.x, e.y);
  } else if(e.button == 2 && !e.shiftKey && e.ctrlKey) {
    g_cameraController.setDragMode(
        o3djs.cameracontroller.DragMode.DOLLY_IN_OUT, e.x, e.y);
  } else if(e.button == 2 && e.shiftKey && e.ctrlKey) {
    g_cameraController.setDragMode(
        o3djs.cameracontroller.DragMode.DOLLY_ZOOM, e.x, e.y);
  } else if(e.button == 1) {
    g_cameraController.setDragMode(
        o3djs.cameracontroller.DragMode.MOVE_CENTER_IN_VIEW_PLANE, e.x, e.y);
  } else if(e.button == 0) {
    g_manager.mousedown(e.x, e.y,
                        g_mainViewInfo.drawContext.view,
                        g_mainViewInfo.drawContext.projection,
                        g_client.width,
                        g_client.height);
  }
}

function onMouseMove(e) {
  g_cameraController.mouseMoved(e.x, e.y);

  // You can call this function here, or pass it to the CameraController
  // as the onChange callback.
  //updateViewAndProjectionMatrices();

  g_manager.mousemove(e.x, e.y,
                      g_mainViewInfo.drawContext.view,
                      g_mainViewInfo.drawContext.projection,
                      g_client.width,
                      g_client.height);
  g_manager.updateInactiveManipulators();
}

function onMouseUp(e) {
  g_cameraController.setDragMode(
      o3djs.cameracontroller.DragMode.NONE, e.x, e.y);

  g_manager.mouseup();
  g_manager.updateInactiveManipulators();
}

/**
 * Initializes global variables and libraries.
 */
function initGlobals(clientElements) {
  g_o3dElement = clientElements[0];
  window.g_client = g_client = g_o3dElement.client;
  g_o3d = g_o3dElement.o3d;
  g_math = o3djs.math;

  // Create a pack to manage the objects created.
  g_mainPack = g_client.createPack();

  // Make a root transform for our scene.
  g_mainRoot = g_mainPack.createObject('Transform');

  // Create the render graph for the scene view.
  g_mainViewInfo = o3djs.rendergraph.createBasicView(
      g_mainPack,
      g_mainRoot,
      g_client.renderGraphRoot);
}

/**
 * Sets up reasonable view and projection matrices.
 */
function initContext() {
  // Set up our CameraController.
  g_cameraController = o3djs.cameracontroller.createCameraController(
      [0, 2, 0],            // centerPos
      23,                   // backpedal
      0,                    // heightAngle
      0,                    // rotationAngle
      g_math.degToRad(15),  // fieldOfViewAngle
      updateViewAndProjectionMatrices); // opt_onChange

  updateViewAndProjectionMatrices();
}

function updateViewAndProjectionMatrices() {
  g_mainViewInfo.drawContext.view = g_cameraController.calculateViewMatrix();

  // Set up a perspective transformation for the projection.
  g_mainViewInfo.drawContext.projection = g_math.matrix4.perspective(
      g_cameraController.fieldOfViewAngle * 2,  // Frustum angle.
      g_o3dElement.clientWidth / g_o3dElement.clientHeight, // Aspect ratio.
      1,                                        // Near plane.
      5000);                                    // Far plane.
}

/**
 * Creates shapes using the primitives utility library, and adds them to the
 * transform graph at the root node.
 */
function createShapes() {
  // Create a little tree-like hierarchy of cubes
  createCubeTree(2, 1.5, [0, 0, 0], g_mainRoot);
  g_lastCubeTransform.scale(3, 1, 1);
}

/**
 * Creates a small tree of cubes to demonstrate interaction with a
 * hierarchy of shapes.
 */
function createCubeTree(depth, edgeLength, translation, parent) {
  var cur = createCube(edgeLength, translation, parent);
  if (depth > 0) {
    createCubeTree(depth - 1,
                   edgeLength / 1.5,
                   o3djs.math.addVector(translation,
                                        [-1.2 * edgeLength,
                                          1.0 * edgeLength,
                                          0]),
                   cur);
    createCubeTree(depth - 1,
                   edgeLength / 1.5,
                   o3djs.math.addVector(translation,
                                        [1.2 * edgeLength,
                                         1.0 * edgeLength,
                                         0]),
                   cur);
  }
  return cur;
}

/**
 * Creates a cube shape using the primitives utility library, with an
 * optional translation and parent. Returns the newly-created
 * transform for the cube.
 */
function createCube(edgeLength, opt_translation, opt_parent) {
  var cube = o3djs.primitives.createCube(
      g_mainPack,
      // A green phong-shaded material.
      o3djs.material.createBasicMaterial(g_mainPack,
                                         g_mainViewInfo,
                                         [0, 1, 0, 1]),
      edgeLength);
  var transform = g_mainPack.createObject('Transform');
  g_lastCubeTransform = transform;
  transform.addShape(cube);
  if (opt_translation) {
    transform.translate(opt_translation);
  }
  if (opt_parent) {
    transform.parent = opt_parent;
  } else {
    transform.parent = g_mainRoot;
  }
  g_primitives.push(transform);
  return transform;
}

/**
 * Creates manipulators attached to the objects we've just created.
 */
function setupManipulators() {
  // Create a separate pack for the manipulators so they don't get mixed in
  // with the main scene's objects.
  var pack = g_client.createPack();

  // Create a root transform for the manipulators so they are 100% separate
  // from the scene's transforms.
  var manipulatorRoot = pack.createObject('Transform');

  g_manager = o3djs.manipulators.createManager(
      pack,
      manipulatorRoot,
      g_client.renderGraphRoot,
      g_mainViewInfo.root.priority + 1,
      g_mainViewInfo.drawContext);

  // Actually construct the manips. This function is implemented in the html
  // sample files that include this file, as it is different for each sample.
  createManipulators();
}

/**
 * Removes any callbacks so they don't get called after the page has unloaded.
 */
function unload() {
  if (g_client) {
    g_client.cleanup();
  }
}
