module Webmachine
  # How to get your Webmachine app running:
  #
  #   MyApp = Webmachine::Application.new do |app|
  #     app.routes do
  #       add [:*], AssetResource
  #     end
  #   end
  #
  #   MyApp.run
  #
  class Application
    extend Forwardable

    def_delegators :dispatcher, :add_route

    # @return [Dispatcher] the current dispatcher
    attr_reader :dispatcher

    # Create an Application instance
    #
    # An instance of application contains Adapter configuration and
    # a Dispatcher instance which can be configured with Routes.
    #
    # @param [Webmachine::Dispatcher] dispatcher
    #   a Webmachine::Dispatcher
    #
    # @yield [app]
    #   a block in which to configure this Application
    # @yieldparam [Application]
    #   the Application instance being initialized
    def initialize(dispatcher = Dispatcher.new)
      @dispatcher    = dispatcher

      yield self if block_given?
    end

    # Evaluates the passed block in the context of {Webmachine::Dispatcher}
    # for use in adding a number of routes at once.
    #
    # @return [Application, Array<Route>]
    #   self if configuring, or an Array of Routes otherwise
    #
    # @see Webmachine::Dispatcher#add_route
    def routes(&block)
      if block_given?
        dispatcher.instance_eval(&block)
        self
      else
        dispatcher.routes
      end
    end
  end

  # @return [Application] the default global Application
  def self.application
    @application ||= Application.new
  end
end
