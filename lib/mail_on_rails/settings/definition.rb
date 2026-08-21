# frozen_string_literal: true

require_relative "../netserv/config"

module MailOnRails
  module Settings
    # One configuration knob's metadata and typing: how its raw forms (an
    # environment variable, an initializer value, a database row) become a
    # typed value, and which tiers may supply it (see Settings for the
    # precedence rules). Stdlib-only - definitions are read on server
    # accept/session paths that load with zero Rails in the process.
    class Definition
      TYPES = %i[integer boolean string list addr].freeze
      SCOPES = %i[static dynamic].freeze

      attr_reader :name, :type, :default, :env, :scope, :category, :min, :max, :desc

      def initialize(name:, type:, default:, scope:, category:, env: nil, min: nil, max: nil,
                     secret: false, normalize: nil, validate: nil, desc: nil)
        raise ArgumentError, "unknown setting type #{type.inspect}" unless TYPES.include?(type)
        raise ArgumentError, "scope must be one of #{SCOPES.join("/")}" unless SCOPES.include?(scope)

        @name = name
        @type = type
        @default = default.is_a?(Array) ? default.freeze : default
        @env = env
        @scope = scope
        @category = category
        @min = min
        @max = max
        @secret = secret
        @normalize = normalize
        @validate = validate
        @desc = desc
      end

      def dynamic? = @scope == :dynamic
      def static? = @scope == :static
      def secret? = @secret

      # The ENV tier's value: the default when the variable is unset, the
      # parsed variable otherwise. Integer parsing goes through
      # Netserv::Config so a bad value fails with the same actionable
      # message it always has. Booleans keep the legacy asymmetric
      # semantics the variables shipped with: a default-on switch is
      # disabled only by "0", a default-off switch is enabled only by "1"
      # (Settings::Check warns about "true"/"yes"/"off" spellings).
      # Strings are deliberately not validated here - a legacy variable
      # that never went through validation must not start failing boots;
      # `check` reports it instead.
      def env_value
        return default unless env

        raw = ENV.fetch(env) { return default }
        case type
        when :integer then Netserv::Config.int(env, default, min: min || 0, max: max)
        when :boolean then default ? raw != "0" : raw == "1"
        when :list then parse_list(raw)
        else normalize(raw)
        end
      end

      # Strict typing for the explicitly-written tiers (initializer
      # overrides, database rows): raises ArgumentError/TypeError on junk -
      # the settings UI turns that into a flash alert, an initializer typo
      # fails the boot. nil passes through untouched ("no value").
      def coerce(value)
        return nil if value.nil?

        value = case type
        when :integer then coerce_integer(value)
        when :boolean then coerce_boolean(value)
        when :list then value.is_a?(Array) ? clean_list(value) : parse_list(value.to_s)
        else normalize(value.to_s)
        end
        @validate&.call(value) unless value.nil?
        value
      end

      # The canonical string form stored in the settings table.
      def serialize(value)
        case type
        when :boolean then value ? "1" : "0"
        when :list then Array(value).join(",")
        else value.to_s
        end
      end

      private

      def coerce_integer(value)
        int = begin
          Integer(value)
        rescue ArgumentError, TypeError
          raise ArgumentError, "#{name} must be an integer, got #{value.inspect}"
        end
        low = min || 0
        if int < low || (max && int > max)
          range = max ? "between #{low} and #{max}" : ">= #{low}"
          raise ArgumentError, "#{name} must be #{range}, got #{int}"
        end
        int
      end

      def coerce_boolean(value)
        case value
        when true, "1", "true" then true
        when false, "0", "false" then false
        else raise ArgumentError, "#{name} must be a boolean (1/0), got #{value.inspect}"
        end
      end

      def normalize(string)
        string = string.strip if type == :addr
        string = @normalize.call(string) if @normalize
        string
      end

      def parse_list(raw)
        clean_list(raw.split(/[\s,]+/))
      end

      def clean_list(values)
        values.map { |v| v.to_s.strip }.reject(&:empty?).freeze
      end
    end
  end
end
