from ortools.constraint_solver import routing_enums_pb2
from ortools.constraint_solver import pywrapcp
from .distance_matrix import distance_matrix


def create_data_model(matrix,location_weights,vehicle_wt_capacities,vehicle_order_capcity,  depot=0):
    """Stores the data for the problem."""
    data={}
    data['distance_matrix'] = matrix
    data['location_weights'] = location_weights
    data['location_weights'][depot] = 0
    data['vehicle_weight_capacities'] = vehicle_wt_capacities
    data['order_weight'] = [1 for i in range(len(location_weights))]
    data['order_weight'][depot]=0
    data['vehicle_order_capacity'] = vehicle_order_capcity
    data['num_vehicles'] = len(vehicle_order_capcity)
    data['depot'] = depot
    return data


def return_solution(data, manager, routing, solution):
    """Prints solution on console."""
    # print(f'Objective: {solution.ObjectiveValue()}')
    max_route_distance = 0
    total_distance = 0
    total_weight = 0
    total_orders = 0
    k = [[] for i in range(data['num_vehicles'])]
    vehicle_route = dict(zip(range(data['num_vehicles']), k))
    for vehicle_id in range(data['num_vehicles']):
        index = routing.Start(vehicle_id)
        route_distance = 0
        route_weight = 0
        route_orders = 0
        while not routing.IsEnd(index):
            node_index = manager.IndexToNode(index)
            vehicle_route[vehicle_id].append(node_index)
            route_weight += data['location_weights'][node_index]
            route_orders += data['order_weight'][node_index]
            previous_index = index
            index = solution.Value(routing.NextVar(index))
            route_distance += routing.GetArcCostForVehicle(
                previous_index, index, vehicle_id)
        vehicle_route[vehicle_id].append(manager.IndexToNode(index))
        vehicle_route[vehicle_id] = [vehicle_route[vehicle_id], route_distance, route_weight, route_orders]
        total_distance += route_distance
        total_weight += route_weight
        total_orders += route_orders
        max_route_distance = max(route_distance, max_route_distance)
    return [vehicle_route, max_route_distance]


def optimisation(matrix,location_weights,vehicle_wt_capacities,vehicle_order_capcity,  depot=0):
    """Solve the CVRP problem."""
    # Instantiate the data problem.
    data = create_data_model(matrix,location_weights,vehicle_wt_capacities,vehicle_order_capcity,  depot=0)

    # Create the routing index manager.
    manager = pywrapcp.RoutingIndexManager(len(data['distance_matrix']),
                                           data['num_vehicles'], data['depot'])

    # Create Routing Model.
    routing = pywrapcp.RoutingModel(manager)

    # Create and register a transit callback.
    def distance_callback(from_index, to_index):
        """Returns the distance between the two nodes."""
        # Convert from routing variable Index to distance matrix NodeIndex.
        from_node = manager.IndexToNode(from_index)
        to_node = manager.IndexToNode(to_index)
        return data['distance_matrix'][from_node][to_node]

    transit_callback_index = routing.RegisterTransitCallback(distance_callback)

    # Define cost of each arc.
    routing.SetArcCostEvaluatorOfAllVehicles(transit_callback_index)

    # Add Capacity constraint.
    def weight_callback(from_index):
        """Returns the demand of the node."""
        # Convert from routing variable Index to demands NodeIndex.
        from_node = manager.IndexToNode(from_index)
        return data['location_weights'][from_node]

    def order_callback(from_index):
        """Returns the demand of the node."""
        # Convert from routing variable Index to demands NodeIndex.
        from_node = manager.IndexToNode(from_index)
        return data['order_weight'][from_node]

    weight_callback_index = routing.RegisterUnaryTransitCallback(
        weight_callback)
    order_callback_index = routing.RegisterUnaryTransitCallback(
        order_callback)
    routing.AddDimensionWithVehicleCapacity(
        weight_callback_index,
        0,  # null capacity slack
        data['vehicle_weight_capacities'],  # vehicle maximum capacities
        True,  # start cumul to zero
        'Weight_Capacity')
    routing.AddDimensionWithVehicleCapacity(
        order_callback_index,
        0,  # null capacity slack
        data['vehicle_order_capacity'],  # vehicle maximum capacities
        True,  # start cumul to zero
        'Order_Capacity')
    # Setting first solution heuristic.
    search_parameters = pywrapcp.DefaultRoutingSearchParameters()
    search_parameters.first_solution_strategy = (
        routing_enums_pb2.FirstSolutionStrategy.PATH_CHEAPEST_ARC)
    search_parameters.local_search_metaheuristic = (
        routing_enums_pb2.LocalSearchMetaheuristic.GUIDED_LOCAL_SEARCH)
    # search_parameters.time_limit.FromSeconds(1)
    search_parameters.time_limit.seconds = 10
    # Solve the problem.
    solution = routing.SolveWithParameters(search_parameters)

    # Print solution on console.
    if solution:
        # print_solution(data, manager, routing, solution)
        return return_solution(data, manager, routing, solution)
    else:
        # print('No solution found !')
        return {}


def generate_optimised_way(coords,location_weights,vehicle_wt_capacities,vehicle_order_capcity,vehicle_names,vehicle_id,location_names,due_amount,phone_number,invoice_number,invoice_id,orderidlist,  depot=0):
    matrix=distance_matrix(coords).euclidean_matrix_raw()
    sol = optimisation(matrix,location_weights,vehicle_wt_capacities,vehicle_order_capcity,  depot=0)
    # print("\\\\\\\\ ",sol)
    if sol:
        

        names = location_names
        final_result = {}
        for key in sol[0].keys():
            # print("keys = ",key)
            final_result[vehicle_id[key]] = [[names[i],due_amount[i],phone_number[i],invoice_number[i],coords[i],invoice_id[i],vehicle_names[key],location_weights[i],orderidlist[i]] for i in sol[0][key][0]]
            final_result[vehicle_id[key]] = [final_result[vehicle_id[key]],
                                                   [sol[0][key][1], sol[0][key][2], sol[0][key][3]]]
            # print("what the fuck:   ",key,vehicle_id[key],final_result.keys())
        return final_result
    else:
        print('No Solution')
        return {}
if __name__ == '__main__':
    
    # coordinate_data=pd.read_csv('test.csv')
    coords=['83.8688 26.5846', '26.844785 81.009478', '26.844785 81.009478', '26.84735656 80.99673193', '26.84939007 81.05801672', '26.89309593 81.07272327', '26.87197829 80.99645969', '26.86110917 81.03994735', '26.85212501 81.04984738', '26.85182349 81.02205835', 'N 26°50\'46.8636"  E 80°57\'52.2252"',  'N 26°52\'35.3316"    E 80°59\'34.1376"', '26.87720028 80.97552001', '26.88881004 81.05653714', 'N 26°52\'34.2012"  E 80°59\'28.0968"', 'N 26°50\'52.5732" E 80°56\'22.3404"']
    location_weights=[0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0] 
    vehicle_wt_capacities=[30]
    vehicle_order_capcity=[80]
    vehicle_names=['DriverName123']
    location_names= ['WareHouse',  '11 Spices Restaurant', 'Dilip Centre', 'Kedar Tiwari(Lavlai)', 'Ravi Yadav Batasa (Mp)', 'Shubham Chola Kulcha', 'Try D Taste Fast Food Eatery', 'Shubham Chhola Pudi', 'Purvanchal Matan Do Pyajaa', 'Karan Tiffin ', 'Diamond Boys Hostel', 'Tea Bar And Garden Restaurant', 'Agrawal Bhojanalay', 'Swaad Ek Parampara', 'V2 Cafe', 'Raj Hostels ']
    k=generate_optimised_way(coords,location_weights,vehicle_wt_capacities,vehicle_order_capcity,vehicle_names,location_names,  depot=0)
    print(k)
    